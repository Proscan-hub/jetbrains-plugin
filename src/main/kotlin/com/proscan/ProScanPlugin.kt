/**
 * ProScan JetBrains Plugin
 *
 * Provides security scanning integration for IntelliJ IDEA, WebStorm,
 * PyCharm, GoLand, and other JetBrains IDEs.
 *
 * Features:
 *   - External annotator for real-time inline findings
 *   - Tool window with findings tree
 *   - File scan on save
 *   - Workspace/project scan
 *   - OAuth2/OIDC SSO authentication
 *   - Quick-fix intentions from ProScan remediation
 */
package com.proscan

import com.intellij.codeInsight.daemon.DaemonCodeAnalyzer
import com.intellij.codeInsight.intention.IntentionAction
import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.generateServiceName
import com.intellij.ide.BrowserUtil
import com.intellij.ide.passwordSafe.PasswordSafe
import com.intellij.lang.annotation.AnnotationHolder
import com.intellij.lang.annotation.ExternalAnnotator
import com.intellij.lang.annotation.HighlightSeverity
import com.intellij.notification.NotificationGroupManager
import com.intellij.notification.NotificationType
import com.intellij.openapi.actionSystem.AnAction
import com.intellij.openapi.actionSystem.AnActionEvent
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.command.WriteCommandAction
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.editor.Document
import com.intellij.openapi.editor.Editor
import com.intellij.openapi.fileEditor.FileDocumentManager
import com.intellij.openapi.project.Project
import com.intellij.openapi.project.ProjectManager
import com.intellij.openapi.startup.StartupActivity
import com.intellij.openapi.vfs.VirtualFile
import com.intellij.openapi.wm.StatusBar
import com.intellij.openapi.wm.StatusBarWidget
import com.intellij.openapi.wm.StatusBarWidgetFactory
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.psi.PsiFile
import com.intellij.ui.content.ContentFactory
import java.awt.event.MouseEvent
import java.net.InetSocketAddress
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.security.SecureRandom
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import javax.swing.*
import javax.swing.tree.DefaultMutableTreeNode
import javax.swing.tree.DefaultTreeModel
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpServer
import java.util.concurrent.atomic.AtomicBoolean

private const val TOKEN_STORAGE_KEY = "proscan.sso.tokens"
private const val CALLBACK_PORT = 48372
private const val CALLBACK_PATH = "/callback"

// ─── Data Classes ────────────────────────────────────────────────────────────

data class ProScanFinding(
    val id: String = "",
    val rule_id: String = "",
    val title: String = "",
    val description: String = "",
    val severity: String = "",
    val file_path: String = "",
    val line_start: Int = 0,
    val line_end: Int = 0,
    val column_start: Int = 0,
    val column_end: Int = 0,
    val code_snippet: String = "",
    val cwe_ids: List<String> = emptyList(),
    val remediation: Remediation? = null
)

data class Remediation(
    val description: String = "",
    val suggested_fix: String = ""
)

data class ScanResponse(
    val scan: ScanState
)

data class ScanState(
    val id: String = "",
    val status: String = "",
    val progress: Int = 0,
    val findings_count: Int = 0
)

data class FindingsResponse(
    val findings: List<ProScanFinding> = emptyList()
)

data class AutofixSuggestion(
    val finding_id: String = "",
    val file_path: String = "",
    val line_start: Int = 0,
    val line_end: Int = 0,
    val column_start: Int = 0,
    val column_end: Int = 0,
    val original_code: String = "",
    val suggested_fix: String = "",
    val description: String = ""
)

data class AutofixResponse(
    val suggestion: AutofixSuggestion? = null
)

// ─── Settings ────────────────────────────────────────────────────────────────

data class ProScanSettings(
    var serverUrl: String = "http://localhost:8080",
    var apiKey: String = "",
    var autoScan: Boolean = true,
    var severityThreshold: String = "low",
    var ssoIssuerUrl: String = "",
    var ssoClientId: String = "proscan-jetbrains",
    var ssoClientSecret: String = ""
)

data class SSOTokens(
    val access_token: String = "",
    val refresh_token: String? = null,
    val expires_in: Int? = null,
    val token_type: String? = null,
    var expires_at: Long? = null
)

@Service(Service.Level.APP)
@State(name = "ProScanSettings", storages = [Storage("proscan.xml")])
class ProScanSettingsService : PersistentStateComponent<ProScanSettings> {
    private var state = ProScanSettings()

    override fun getState(): ProScanSettings = state
    override fun loadState(state: ProScanSettings) { this.state = state }

    companion object {
        fun getInstance(): ProScanSettingsService =
            ApplicationManager.getApplication().getService(ProScanSettingsService::class.java)
    }
}

// ─── SSO Token Storage ────────────────────────────────────────────────────────

object ProScanSSOStorage {
    private val credentialAttributes = CredentialAttributes(generateServiceName("ProScan", TOKEN_STORAGE_KEY))

    fun getTokens(): SSOTokens? {
        val raw = PasswordSafe.instance.getPassword(credentialAttributes) ?: return null
        return try {
            val obj = Gson().fromJson(raw, SSOTokens::class.java)
            obj
        } catch (_: Exception) { null }
    }

    fun storeTokens(tokens: SSOTokens) {
        val toStore = tokens.copy(
            expires_at = tokens.expires_in?.let { System.currentTimeMillis() / 1000 + it }
        )
        PasswordSafe.instance.setPassword(credentialAttributes, Gson().toJson(toStore))
    }

    fun clearTokens() {
        PasswordSafe.instance.setPassword(credentialAttributes, null)
    }
}

// ─── Login State (for UI) ────────────────────────────────────────────────────

object ProScanLoginState {
    private val loggedIn = AtomicBoolean(false)

    fun isLoggedIn(): Boolean = loggedIn.get()
    fun setLoggedIn(value: Boolean) { loggedIn.set(value) }
}

// ─── API Client ──────────────────────────────────────────────────────────────

object ProScanClient {
    private val httpClient = HttpClient.newHttpClient()
    private val gson = Gson()

    private fun settings() = ProScanSettingsService.getInstance().state

    fun getAccessToken(): String? {
        val apiKey = settings().apiKey
        if (apiKey.isNotEmpty()) return apiKey

        val tokens = ProScanSSOStorage.getTokens() ?: return null
        if (tokens.access_token.isEmpty()) return null

        val now = System.currentTimeMillis() / 1000
        val expiresAt = tokens.expires_at ?: Long.MAX_VALUE
        if (expiresAt > now + 60) return tokens.access_token

        if (tokens.refresh_token != null) {
            val refreshed = refreshTokens(tokens)
            if (refreshed != null) return refreshed.access_token
        }
        return null
    }

    private fun refreshTokens(tokens: SSOTokens): SSOTokens? {
        val refreshToken = tokens.refresh_token ?: return null
        val cfg = getSSOConfigPublic()
        val body = "grant_type=refresh_token&refresh_token=${java.net.URLEncoder.encode(refreshToken, "UTF-8")}" +
            "&client_id=${java.net.URLEncoder.encode(cfg.clientId, "UTF-8")}" +
            (if (cfg.clientSecret.isNotEmpty()) "&client_secret=${java.net.URLEncoder.encode(cfg.clientSecret, "UTF-8")}" else "")
        return try {
            val req = HttpRequest.newBuilder()
                .uri(URI.create(cfg.tokenUrl))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()
            val res = httpClient.send(req, HttpResponse.BodyHandlers.ofString())
            if (res.statusCode() != 200) return null
            val newTokens = gson.fromJson(res.body(), SSOTokens::class.java)
            ProScanSSOStorage.storeTokens(newTokens)
            newTokens
        } catch (_: Exception) { null }
    }

    fun <T> apiGet(path: String, type: java.lang.reflect.Type): T {
        val url = "${settings().serverUrl}/api/v2$path"
        val builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .GET()
        getAccessToken()?.let { builder.header("Authorization", "Bearer $it") }
        val response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() == 401) {
            ProScanSSOStorage.clearTokens()
            ProScanLoginState.setLoggedIn(false)
            throw RuntimeException("ProScan API error: 401 Unauthorized")
        }
        if (!response.body().isNullOrEmpty()) {
            return gson.fromJson(response.body(), type)
        }
        throw RuntimeException("ProScan API error: ${response.statusCode()}")
    }

    fun <T> apiPost(path: String, body: Any, type: java.lang.reflect.Type): T {
        val url = "${settings().serverUrl}/api/v2$path"
        val jsonBody = gson.toJson(body)
        val builder = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Content-Type", "application/json")
            .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
        getAccessToken()?.let { builder.header("Authorization", "Bearer $it") }
        val response = httpClient.send(builder.build(), HttpResponse.BodyHandlers.ofString())
        if (response.statusCode() == 401) {
            ProScanSSOStorage.clearTokens()
            ProScanLoginState.setLoggedIn(false)
            throw RuntimeException("ProScan API error: 401 Unauthorized")
        }
        if (!response.body().isNullOrEmpty()) {
            return gson.fromJson(response.body(), type)
        }
        throw RuntimeException("ProScan API error: ${response.statusCode()}")
    }

    fun startScan(localPath: String): ScanResponse {
        val body = mapOf("source_type" to "local", "local_path" to localPath)
        return apiPost("/scanner/sast/scan", body, ScanResponse::class.java)
    }

    fun getScanState(scanId: String): ScanState {
        return apiGet("/scanner/sast/scans/$scanId", ScanState::class.java)
    }

    fun getFindings(scanId: String): List<ProScanFinding> {
        val result: FindingsResponse = apiGet(
            "/scanner/sast/scans/$scanId/results",
            FindingsResponse::class.java
        )
        return result.findings
    }
}

// ─── Findings Cache (per-project) ────────────────────────────────────────────

@Service(Service.Level.PROJECT)
class ProScanFindingsCache {
    var findings: List<ProScanFinding> = emptyList()
        private set

    fun update(newFindings: List<ProScanFinding>) {
        findings = newFindings
    }

    fun getForFile(filePath: String): List<ProScanFinding> {
        return findings.filter { it.file_path.endsWith(filePath) || filePath.endsWith(it.file_path) }
    }

    fun clear() { findings = emptyList() }
}

// ─── Quick-Fix (IntentionAction) ──────────────────────────────────────────────

class ProScanQuickFix(private val finding: ProScanFinding) : IntentionAction {

    override fun getText(): String {
        val desc = finding.remediation?.description
        return if (!desc.isNullOrBlank()) "ProScan: $desc" else "ProScan: Apply suggested fix for ${finding.title}"
    }

    override fun getFamilyName(): String = "ProScan Quick Fix"

    override fun isAvailable(project: Project, editor: Editor?, file: PsiFile?): Boolean = true

    override fun startInWriteAction(): Boolean = false

    override fun invoke(project: Project, editor: Editor?, file: PsiFile?) {
        val doc = editor?.document ?: return

        // If we already have a suggested fix from the finding's remediation, apply it directly.
        val inlineFix = finding.remediation?.suggested_fix
        if (!inlineFix.isNullOrBlank()) {
            applyFixToDocument(project, doc, finding, inlineFix)
            return
        }

        // Otherwise, call the backend autofix API on a pooled thread.
        ApplicationManager.getApplication().executeOnPooledThread {
            try {
                val response: AutofixResponse = ProScanClient.apiPost(
                    "/autofix/generate",
                    mapOf("finding_id" to finding.id, "file_path" to finding.file_path),
                    AutofixResponse::class.java
                )
                val suggestion = response.suggestion
                if (suggestion != null && suggestion.suggested_fix.isNotBlank()) {
                    ApplicationManager.getApplication().invokeLater {
                        applyFixToDocument(project, doc, finding, suggestion.suggested_fix)
                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("ProScan")
                            .createNotification("ProScan: Autofix applied", NotificationType.INFORMATION)
                            .notify(project)
                    }
                } else {
                    ApplicationManager.getApplication().invokeLater {
                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("ProScan")
                            .createNotification("ProScan: No autofix suggestion available", NotificationType.WARNING)
                            .notify(project)
                    }
                }
            } catch (e: Exception) {
                ApplicationManager.getApplication().invokeLater {
                    NotificationGroupManager.getInstance()
                        .getNotificationGroup("ProScan")
                        .createNotification("ProScan autofix failed: ${e.message}", NotificationType.ERROR)
                        .notify(project)
                }
            }
        }
    }

    private fun applyFixToDocument(project: Project, doc: Document, finding: ProScanFinding, fixText: String) {
        val lineStart = (finding.line_start - 1).coerceIn(0, doc.lineCount - 1)
        val lineEnd = (finding.line_end - 1).coerceIn(lineStart, doc.lineCount - 1)
        val startOffset = doc.getLineStartOffset(lineStart) + (finding.column_start - 1).coerceAtLeast(0)
        val endOffset = if (finding.column_end > 0) {
            doc.getLineStartOffset(lineEnd) + finding.column_end
        } else {
            doc.getLineEndOffset(lineEnd)
        }.coerceAtMost(doc.textLength)

        WriteCommandAction.runWriteCommandAction(project, "ProScan: Apply Fix", null, {
            doc.replaceString(startOffset, endOffset, fixText)
        })
    }
}

// ─── External Annotator (inline squiggles) ───────────────────────────────────

class ProScanAnnotator : ExternalAnnotator<PsiFile, List<ProScanFinding>>() {

    override fun collectInformation(file: PsiFile): PsiFile = file

    override fun doAnnotate(psiFile: PsiFile): List<ProScanFinding> {
        val project = psiFile.project
        val cache = project.getService(ProScanFindingsCache::class.java)
        val vf = psiFile.virtualFile ?: return emptyList()
        return cache.getForFile(vf.path)
    }

    override fun apply(file: PsiFile, findings: List<ProScanFinding>, holder: AnnotationHolder) {
        val doc = FileDocumentManager.getInstance().getDocument(file.virtualFile ?: return) ?: return
        val settings = ProScanSettingsService.getInstance().state
        val threshold = severityOrder(settings.severityThreshold)

        for (f in findings) {
            if (severityOrder(f.severity) > threshold) continue

            val lineStart = (f.line_start - 1).coerceIn(0, doc.lineCount - 1)
            val lineEnd = (f.line_end - 1).coerceIn(lineStart, doc.lineCount - 1)
            val startOffset = doc.getLineStartOffset(lineStart) + (f.column_start - 1).coerceAtLeast(0)
            val endOffset = if (f.column_end > 0) {
                doc.getLineStartOffset(lineEnd) + f.column_end
            } else {
                doc.getLineEndOffset(lineEnd)
            }.coerceAtMost(doc.textLength)

            if (startOffset >= endOffset) continue

            val severity = mapSeverity(f.severity)
            val quickFix = ProScanQuickFix(f)
            holder.newAnnotation(severity, "[ProScan] ${f.title}")
                .range(com.intellij.openapi.util.TextRange(startOffset, endOffset))
                .tooltip("<b>${f.severity.uppercase()}: ${f.title}</b><br>${f.description}<br>" +
                        (f.cwe_ids.joinToString(", ")))
                .withFix(quickFix)
                .create()
        }
    }

    private fun mapSeverity(sev: String): HighlightSeverity = when (sev.lowercase()) {
        "critical", "high" -> HighlightSeverity.ERROR
        "medium" -> HighlightSeverity.WARNING
        "low" -> HighlightSeverity.WEAK_WARNING
        else -> HighlightSeverity.INFORMATION
    }

    private fun severityOrder(sev: String): Int = when (sev.lowercase()) {
        "critical" -> 0; "high" -> 1; "medium" -> 2; "low" -> 3; else -> 4
    }
}

// ─── Tool Window ─────────────────────────────────────────────────────────────

class ProScanToolWindowFactory : ToolWindowFactory {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = ProScanToolWindowPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "Findings", false)
        toolWindow.contentManager.addContent(content)
    }
}

class ProScanToolWindowPanel(private val project: Project) : JPanel() {
    private val treeModel = DefaultTreeModel(DefaultMutableTreeNode("Security Findings"))
    private val tree = JTree(treeModel)
    private val scanButton = JButton("Scan Project")
    private val clearButton = JButton("Clear")
    private val statusLabel = JLabel("Ready")

    init {
        layout = java.awt.BorderLayout()

        val toolbar = JPanel()
        toolbar.add(scanButton)
        toolbar.add(clearButton)
        toolbar.add(statusLabel)
        add(toolbar, java.awt.BorderLayout.NORTH)
        add(JScrollPane(tree), java.awt.BorderLayout.CENTER)

        scanButton.addActionListener { scanProject() }
        clearButton.addActionListener { clearFindings() }

        // Refresh from cache.
        refreshTree()
    }

    private fun scanProject() {
        val basePath = project.basePath ?: return
        statusLabel.text = "Scanning..."
        scanButton.isEnabled = false

        Thread {
            try {
                val result = ProScanClient.startScan(basePath)
                val scanId = result.scan.id

                // Poll for completion.
                for (i in 0..300) {
                    Thread.sleep(2000)
                    val state = ProScanClient.getScanState(scanId)
                    SwingUtilities.invokeLater {
                        statusLabel.text = "${state.progress}% (${state.findings_count} findings)"
                    }
                    if (state.status == "completed" || state.status == "failed") {
                        if (state.status == "completed") {
                            val findings = ProScanClient.getFindings(scanId)
                            val cache = project.getService(ProScanFindingsCache::class.java)
                            cache.update(findings)
                        }
                        break
                    }
                }

                SwingUtilities.invokeLater {
                    refreshTree()
                    scanButton.isEnabled = true
                    DaemonCodeAnalyzer.getInstance(project).restart()

                    NotificationGroupManager.getInstance()
                        .getNotificationGroup("ProScan")
                        .createNotification("ProScan scan complete", NotificationType.INFORMATION)
                        .notify(project)
                }
            } catch (e: Exception) {
                SwingUtilities.invokeLater {
                    statusLabel.text = "Error: ${e.message}"
                    scanButton.isEnabled = true
                }
            }
        }.start()
    }

    private fun clearFindings() {
        val cache = project.getService(ProScanFindingsCache::class.java)
        cache.clear()
        refreshTree()
        DaemonCodeAnalyzer.getInstance(project).restart()
    }

    private fun refreshTree() {
        val cache = project.getService(ProScanFindingsCache::class.java)
        val root = DefaultMutableTreeNode("Security Findings (${cache.findings.size})")

        // Group by severity.
        val bySeverity = cache.findings.groupBy { it.severity.lowercase() }
        for ((severity, findings) in bySeverity.toSortedMap(compareBy { severityIdx(it) })) {
            val sevNode = DefaultMutableTreeNode("$severity (${findings.size})")
            for (f in findings) {
                sevNode.add(DefaultMutableTreeNode("${f.title} - ${f.file_path}:${f.line_start}"))
            }
            root.add(sevNode)
        }

        treeModel.setRoot(root)
        treeModel.reload()
        statusLabel.text = "${cache.findings.size} findings"
    }

    private fun severityIdx(sev: String): Int = when (sev) {
        "critical" -> 0; "high" -> 1; "medium" -> 2; "low" -> 3; else -> 4
    }
}

// ─── Actions ─────────────────────────────────────────────────────────────────

class ScanProjectAction : AnAction("ProScan: Scan Project") {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val basePath = project.basePath ?: return

        Thread {
            try {
                val result = ProScanClient.startScan(basePath)
                // Scanning happens asynchronously; the tool window polls.
                NotificationGroupManager.getInstance()
                    .getNotificationGroup("ProScan")
                    .createNotification("ProScan scan started (${result.scan.id})", NotificationType.INFORMATION)
                    .notify(project)
            } catch (ex: Exception) {
                NotificationGroupManager.getInstance()
                    .getNotificationGroup("ProScan")
                    .createNotification("ProScan scan failed: ${ex.message}", NotificationType.ERROR)
                    .notify(project)
            }
        }.start()
    }
}

class ScanFileAction : AnAction("ProScan: Scan Current File") {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return
        val file = e.getData(com.intellij.openapi.actionSystem.CommonDataKeys.VIRTUAL_FILE) ?: return

        Thread {
            try {
                val result = ProScanClient.startScan(file.path)
                NotificationGroupManager.getInstance()
                    .getNotificationGroup("ProScan")
                    .createNotification("ProScan file scan started", NotificationType.INFORMATION)
                    .notify(project)
            } catch (ex: Exception) {
                NotificationGroupManager.getInstance()
                    .getNotificationGroup("ProScan")
                    .createNotification("ProScan scan failed: ${ex.message}", NotificationType.ERROR)
                    .notify(project)
            }
        }.start()
    }
}

// ─── SSO Login Action ────────────────────────────────────────────────────────

class LoginWithSSOAction : AnAction("ProScan: Sign in with SSO") {
    override fun actionPerformed(e: AnActionEvent) {
        val project = e.project ?: return

        Thread {
            try {
                val cfg = getSSOConfigPublic()
                val state = ByteArray(16).also { SecureRandom().nextBytes(it) }
                    .joinToString("") { "%02x".format(it) }
                val redirectUri = "http://localhost:$CALLBACK_PORT$CALLBACK_PATH"
                val authUrl = "${cfg.authUrl}?client_id=${java.net.URLEncoder.encode(cfg.clientId, "UTF-8")}" +
                    "&redirect_uri=${java.net.URLEncoder.encode(redirectUri, "UTF-8")}" +
                    "&response_type=code&scope=openid%20offline_access&state=$state"

                val codeHolder = Array<String?>(1) { null }
                val server = HttpServer.create(InetSocketAddress("127.0.0.1", CALLBACK_PORT), 0)
                server.createContext(CALLBACK_PATH) { exchange: HttpExchange ->
                    val uri = exchange.requestURI
                    val params = uri.query?.split("&")?.associate {
                        val parts = it.split("=", limit = 2)
                        parts[0] to java.net.URLDecoder.decode(parts.getOrNull(1) ?: "", "UTF-8")
                    } ?: emptyMap()
                    val code = params["code"]
                    val err = params["error"]
                    val stateReturned = params["state"]

                    val html = when {
                        stateReturned != state -> "<html><body><h1>State mismatch</h1><p>Please close this tab.</p></body></html>"
                        err != null -> "<html><body><h1>Login failed</h1><p>$err</p><p>Please close this tab.</p></body></html>"
                        code != null -> {
                            codeHolder[0] = code
                            "<html><body><h1>Login successful</h1><p>You may close this tab and return to your IDE.</p></body></html>"
                        }
                        else -> "<html><body><h1>Error</h1></body></html>"
                    }
                    exchange.sendResponseHeaders(200, html.toByteArray().size.toLong())
                    exchange.responseBody.use { it.write(html.toByteArray()) }

                    ApplicationManager.getApplication().executeOnPooledThread {
                        Thread.sleep(500)
                        server.stop(0)
                    }
                }
                server.executor = null
                server.start()
                BrowserUtil.browse(authUrl)

                var code: String? = null
                for (i in 0..120) {
                    Thread.sleep(500)
                    code = codeHolder[0]
                    if (code != null) break
                }
                server.stop(0)

                if (code == null) {
                    SwingUtilities.invokeLater {
                        NotificationGroupManager.getInstance()
                            .getNotificationGroup("ProScan")
                            .createNotification("ProScan SSO login failed or was cancelled", NotificationType.ERROR)
                            .notify(project)
                    }
                    return@Thread
                }

                val body = "grant_type=authorization_code&code=$code&redirect_uri=${java.net.URLEncoder.encode(redirectUri, "UTF-8")}&client_id=${java.net.URLEncoder.encode(cfg.clientId, "UTF-8")}" +
                    (if (cfg.clientSecret.isNotEmpty()) "&client_secret=${java.net.URLEncoder.encode(cfg.clientSecret, "UTF-8")}" else "")
                val req = HttpRequest.newBuilder()
                    .uri(URI.create(cfg.tokenUrl))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(body))
                    .build()
                val res = HttpClient.newHttpClient().send(req, HttpResponse.BodyHandlers.ofString())
                if (res.statusCode() != 200) throw Exception("Token exchange failed: ${res.statusCode()} ${res.body()}")

                val tokens = Gson().fromJson(res.body(), SSOTokens::class.java)
                ProScanSSOStorage.storeTokens(tokens)
                ProScanLoginState.setLoggedIn(true)

                SwingUtilities.invokeLater {
                    updateAllStatusBars(project)
                    NotificationGroupManager.getInstance()
                        .getNotificationGroup("ProScan")
                        .createNotification("ProScan: Successfully signed in via SSO", NotificationType.INFORMATION)
                        .notify(project)
                }
            } catch (ex: Exception) {
                SwingUtilities.invokeLater {
                    NotificationGroupManager.getInstance()
                        .getNotificationGroup("ProScan")
                        .createNotification("ProScan SSO login failed: ${ex.message}", NotificationType.ERROR)
                        .notify(project)
                }
            }
        }.start()
    }
}

private fun getSSOConfigPublic(): SSOConfigPublic {
    val s = ProScanSettingsService.getInstance().state
    val issuer = s.ssoIssuerUrl.removeSuffix("/").ifEmpty { s.serverUrl.removeSuffix("/") }
    return SSOConfigPublic(
        authUrl = "$issuer/oauth/authorize",
        tokenUrl = "$issuer/oauth/token",
        clientId = s.ssoClientId.ifEmpty { "proscan-jetbrains" },
        clientSecret = s.ssoClientSecret
    )
}

private data class SSOConfigPublic(val authUrl: String, val tokenUrl: String, val clientId: String, val clientSecret: String)

private fun updateAllStatusBars(project: Project) {
    val frame = com.intellij.openapi.wm.WindowManager.getInstance().getIdeFrame(project) ?: return
    val statusBar = frame.statusBar ?: return
    statusBar.updateWidget(ProScanStatusBarWidget.ID)
}

class LogoutAction : AnAction("ProScan: Sign Out") {
    override fun actionPerformed(e: AnActionEvent) {
        ProScanSSOStorage.clearTokens()
        ProScanLoginState.setLoggedIn(false)
        for (p in ProjectManager.getInstance().openProjects) {
            updateAllStatusBars(p)
        }
        val project = e.project ?: ProjectManager.getInstance().openProjects.firstOrNull()
        NotificationGroupManager.getInstance()
            .getNotificationGroup("ProScan")
            .createNotification("ProScan: Signed out", NotificationType.INFORMATION)
            .notify(project)
    }
}

// ─── Status Bar Widget ──────────────────────────────────────────────────────

class ProScanStatusBarWidget(private val project: Project) : StatusBarWidget {
    companion object {
        const val ID = "ProScan.StatusBar"
    }
    override fun ID(): String = ID
    override fun getPresentation(): StatusBarWidget.WidgetPresentation = presentation
    private val presentation = object : StatusBarWidget.TextPresentation {
        override fun getText(): String =
            if (ProScanClient.getAccessToken() != null) "ProScan \u2713" else "ProScan"
        override fun getTooltipText(): String? =
            if (ProScanClient.getAccessToken() != null) "ProScan: Signed in via SSO" else "ProScan Security Scanner"
        override fun getAlignment(): Float = java.awt.Component.CENTER_ALIGNMENT
        override fun getClickConsumer(): com.intellij.util.Consumer<MouseEvent>? = null
    }
    override fun install(statusBar: StatusBar) {}
    override fun dispose() {}
}

class ProScanStatusBarWidgetFactory : StatusBarWidgetFactory {
    override fun getId(): String = ProScanStatusBarWidget.ID
    override fun getDisplayName(): String = "ProScan"
    override fun isAvailable(project: Project): Boolean = true
    override fun createWidget(project: Project): StatusBarWidget = ProScanStatusBarWidget(project)
}

// ─── Auto-login on startup ───────────────────────────────────────────────────

class ProScanStartupActivity : StartupActivity {
    override fun runActivity(project: Project) {
        val hasToken = ProScanClient.getAccessToken() != null
        ProScanLoginState.setLoggedIn(hasToken)
        updateAllStatusBars(project)
    }
}
