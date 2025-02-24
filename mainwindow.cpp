#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include "ssh_port_forward.h"

#include "job_dialog.h"
#include "password_dialog.h"

#include <iostream>

#include <QDesktopServices>
#include <QInputDialog>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QRegularExpressionMatchIterator>
#include <QUrl>
#include <QUrlQuery>

struct NotebookUrlParts
{
    QString protocol;
    QString host;
    int port;
    QString path;
    QString token;
};

NotebookUrlParts parseNotebookUrl(const QString &urlString)
{
    NotebookUrlParts parts;

    // Create QUrl object from the string
    QUrl url(urlString);

    // Extract basic URL components
    parts.protocol = url.scheme();
    parts.host = url.host();
    parts.port = url.port();
    parts.path = url.path();

    // Parse query parameters to get the token
    QUrlQuery query(url);
    if (query.hasQueryItem("token"))
    {
        parts.token = query.queryItemValue("token");
    }

    return parts;
}

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), m_sshClient(nullptr), m_sshPortForward(nullptr)
{
    ui->setupUi(this);

    m_sshClient = new SSHClient(this);
    m_notebookController = NotebookController::create(m_sshClient);

    // Connect signals

    connect(m_sshClient, &SSHClient::connected, this, &MainWindow::onConnected);
    connect(m_sshClient, &SSHClient::disconnected, this, &MainWindow::onDisconnected);
    connect(m_sshClient, &SSHClient::error, this, &MainWindow::onError);
    connect(m_sshClient, &SSHClient::keyboardInteractivePrompt, this, &MainWindow::onKeyboardInteractivePrompt);
    connect(m_sshClient, &SSHClient::authenticationFailed, this, &MainWindow::onAuthenticationFailed);
    connect(m_sshClient, &SSHClient::authenticationSucceeded, this, &MainWindow::onAuthenticationSucceeded);
    connect(m_sshClient, &SSHClient::tunnelEstablished, this, &MainWindow::onTunnelEstablished);
    connect(m_sshClient, &SSHClient::tunnelClosed, this, &MainWindow::onTunnelClosed);

    connect(m_sshClient, &SSHClient::channelOutputReceived, this, &MainWindow::onChannelOutputReceived);
    connect(m_sshClient, &SSHClient::channelOpened, this, &MainWindow::onChannelOpened);
    connect(m_sshClient, &SSHClient::channelClosed, this, &MainWindow::onChannelClosed);
    connect(m_sshClient, &SSHClient::channelError, this, &MainWindow::onChannelError);

    connect(m_notebookController.get(), &NotebookController::jobTableUpdated, this, &MainWindow::onJobTableUpdated);

    m_sshPortForward = new SSHPortForward(m_sshClient, this);
    connect(m_sshPortForward, &SSHPortForward::forwardingStarted, this, &MainWindow::onForwardingStarted,
            Qt::QueuedConnection);
    connect(m_sshPortForward, &SSHPortForward::forwardingStopped, this, &MainWindow::onForwardingStopped,
            Qt::QueuedConnection);
    connect(m_sshPortForward, &SSHPortForward::error, this, &MainWindow::onForwardError, Qt::QueuedConnection);
    connect(m_sshPortForward, &SSHPortForward::newConnectionEstablished, this,
            &MainWindow::onNewForwardConnectionEstablished, Qt::QueuedConnection);
    connect(m_sshPortForward, &SSHPortForward::connectionClosed, this, &MainWindow::onForwardConnectionClosed,
            Qt::QueuedConnection);

    disableControls();
}

MainWindow::~MainWindow()
{

    delete ui;
}

void MainWindow::disableControls()
{
    ui->connectButton->setEnabled(true);
    ui->newNotebookButton->setEnabled(false);
    ui->refreshButton->setEnabled(false);
    ui->closeNotebookButton->setEnabled(false);
    ui->closeButton->setEnabled(false);
    ui->openNotebookButton->setEnabled(false);
}

void MainWindow::enableControls()
{
    ui->connectButton->setEnabled(false);
    ui->newNotebookButton->setEnabled(true);
    ui->refreshButton->setEnabled(true);
    ui->closeNotebookButton->setEnabled(true);
    ui->closeButton->setEnabled(true);
    ui->openNotebookButton->setEnabled(true);
}

void MainWindow::log(const QString &message)
{
    ui->logEdit->append(message);
}

void MainWindow::onConnected()
{
    ui->statusBar->showMessage("Connected to host");
    log("Connected to host");
}

void MainWindow::onDisconnected()
{
    ui->statusBar->showMessage("Disconnected from host");
    disableControls();
    log("Disconnected from host");
}

void MainWindow::onError(const QString &error)
{
    ui->statusBar->showMessage(error);
    log("Error: " + error);
}

void MainWindow::onAuthenticationFailed()
{
    ui->statusBar->showMessage("Authentication failed.");
    disableControls();
    log("Authentication failed");
}

void MainWindow::onAuthenticationSucceeded()
{
    log("Authentication succeeded");

    ui->statusBar->showMessage("Authentication succeeded.");
    enableControls();

    SSHClient::CommandOptions options;
    options.ptyEnabled = true; // Enable PTY for interactive apps
    options.columns = 120;     // Set reasonable terminal size
    options.rows = 40;
    options.mergeOutput = true; // Merge stderr with stdout
    options.outputMode = SSHClient::PtyOutputMode::StripAll;

    m_sshClient->openCommandChannel(options);

    if (m_sshClient->isCommandChannelOpen())
    {
        log("Command channel is open");
        m_notebookController->initialise();
        m_notebookController->job_table();
    }
}

void MainWindow::onKeyboardInteractivePrompt(const QString &name, const QString &instruction,
                                             const QStringList &prompts)
{
    log("Received keyboard-interactive prompt: " + name + " - " + instruction);

    QStringList responses;
    for (int i = 0; i < prompts.size(); i++)
    {
        QInputDialog dialog;
        dialog.setWindowTitle(name);
        dialog.setLabelText(prompts.at(i));
        if (prompts.at(i).contains("password", Qt::CaseInsensitive))
            dialog.setTextEchoMode(QLineEdit::Password);
        else
            dialog.setTextEchoMode(QLineEdit::Normal);
        dialog.exec();
        responses << dialog.textValue();
    }

    log("Sending keyboard-interactive response: " + responses.join(", "));
    m_sshClient->sendKeyboardInteractiveResponse(responses);
}

void MainWindow::onTunnelEstablished(const QString &bindAddress, uint16_t bindPort)
{
    ui->statusBar->showMessage(QString("Tunnel established on %1:%2").arg(bindAddress).arg(bindPort));
}

void MainWindow::onTunnelClosed(const QString &bindAddress, uint16_t bindPort)
{
    ui->statusBar->showMessage(QString("Tunnel closed on %1:%2").arg(bindAddress).arg(bindPort));
}

void MainWindow::onDataReceived(const QByteArray &data)
{
    ui->textEdit->append(QString::fromUtf8(data));
}

void MainWindow::onForwardingStarted(quint16 localPort)
{
    log("Forwarding started on port " + QString::number(localPort));
}

void MainWindow::onForwardingStopped()
{
    log("Forwarding stopped");
}

void MainWindow::onForwardError(const QString &message)
{
    log("Forwarding error: " + message);
}

void MainWindow::onNewForwardConnectionEstablished(const QString &remoteHost, quint16 remotePort)
{
    log("New connection established to " + remoteHost + ":" + QString::number(remotePort));
}

void MainWindow::onForwardConnectionClosed()
{
    log("Forward connection closed");
}

void MainWindow::onChannelOpened()
{
    log("Command channel opened");
}

void MainWindow::onChannelClosed(int exitStatus)
{
    log("Command channel closed with exit status: " + QString::number(exitStatus));
}

std::vector< QString > extractUrls(const QString &input)
{
    std::vector< QString > urls;

    // Regular expression pattern for URLs
    // This pattern matches common URL formats including http, https, ftp
    QRegularExpression urlRegex(QStringLiteral(R"((https?|ftp):\/\/)"                        // Protocol
                                               R"([\w_-]+(?:(?:\.[\w_-]+)+))"                // Domain name
                                               R"(([\w.,@?^=%&:\/~+#-]*[\w@?^=%&\/~+#-])?)") // Path and query
    );

    // Find all matches in the input string
    QRegularExpressionMatchIterator matchIterator = urlRegex.globalMatch(input);

    // Extract each URL match
    while (matchIterator.hasNext())
    {
        QRegularExpressionMatch match = matchIterator.next();
        urls.push_back(match.captured(0));
    }

    return urls;
}

void MainWindow::onChannelOutputReceived(const QByteArray &data, bool isStderr)
{
    // log("Command output received: " + QString::fromUtf8(data));

    auto receivedString = QString::fromUtf8(data);
    ui->textEdit->append(QString::fromUtf8(data));

    log("----- Command output received ---- ");
    log(receivedString);
    log("----- Command output end --------- ");

    m_notebookController->parseCommandOutput(receivedString);
}

void MainWindow::onChannelError(const QString &error)
{
    log("Command channel error: " + error);
}

void MainWindow::onJobTableUpdated()
{
    log("Updating running table");
    ui->runningTable->clearContents();

    auto jobs = m_notebookController->jobs();

    ui->runningTable->setRowCount(jobs.size());

    ui->runningTable->setColumnCount(4);
    ui->runningTable->setHorizontalHeaderLabels(QStringList() << "ID"
                                                              << "Name"
                                                              << "Status"
                                                              << "URL");

    for (int i = 0; i < jobs.size(); i++)
    {
        auto jobIdItem = new QTableWidgetItem(QString::number(jobs[i].id));
        jobIdItem->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);

        auto jobNameItem = new QTableWidgetItem(jobs[i].name);
        jobNameItem->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);

        auto jobStatusItem = new QTableWidgetItem(jobs[i].status);
        jobStatusItem->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);

        auto jobUrlItem = new QTableWidgetItem(jobs[i].url);
        jobUrlItem->setTextAlignment(Qt::AlignHCenter | Qt::AlignVCenter);

        ui->runningTable->setItem(i, 0, jobIdItem);
        ui->runningTable->setItem(i, 1, jobNameItem);
        ui->runningTable->setItem(i, 2, jobStatusItem);
        ui->runningTable->setItem(i, 3, jobUrlItem);
    }
}

void MainWindow::on_connectButton_clicked()
{
    QString server, username, password;

    // server = "rocky9-vm.lunarc.lu.se";
    // username = "lindemann";

    server = "192.168.86.28";
    username = "lindemann";

    if (m_connectionSettings.useKeyboardInteractive)
    {
        log("Trying to authenticate with KeyboardInteractive");
        m_sshClient->authenticateWithKeyboardInteractive();
        log("isAuthenticated: " + QString::number(m_sshClient->isAuthenticated()));

        if (!m_sshClient->isAuthenticated())
        {
            log("Trying to authenticate with Password");
            // m_sshClient->authenticateWithPassword(ui->passwordEdit->text());
        }
        else
            log("Already authenticated");
    }
    else
    {
        if (PasswordDialog::getConnectionInfo(this, server, username, password))
        {
            m_sshClient->connectToHost(server, username);
            m_sshClient->authenticateWithPassword(password);
        }
        else
        {
            log("Connection cancelled");
            return;
        }
    }
}

void MainWindow::on_disconnectButton_clicked()
{
    m_sshClient->disconnect();

    if (m_sshPortForward != nullptr)
    {
        if (m_sshPortForward->isForwarding())
            m_sshPortForward->stopForwarding();
    }
}

void MainWindow::on_executeButton_clicked()
{
    m_sshClient->executeCommand(ui->commandEdit->text());
    ui->commandEdit->clear();
}

void MainWindow::on_commandEdit_returnPressed()
{
    m_sshClient->executeInChannel(ui->commandEdit->text());
    ui->commandEdit->clear();
}

void MainWindow::on_connectTunnelButton_clicked()
{
}

void MainWindow::on_disconnectTunnelButton_clicked()
{
}

void MainWindow::on_newNotebookButton_clicked()
{
    QString name, notebookEnv, wallTime;
    int tasksPerNode;

    if (JobDialog::getJobInfo(this, name, notebookEnv, wallTime, tasksPerNode))
    {
        m_notebookController->submit(name, notebookEnv, wallTime, tasksPerNode);
    }
    else
    {
        log("Notebook creation cancelled.");
        return;
    }
}

void MainWindow::on_refreshButton_clicked()
{
    m_notebookController->job_table();
}

void MainWindow::on_closeButton_clicked()
{
    m_sshClient->closeCommandChannel();
    m_sshClient->disconnect();
    if (m_sshPortForward != nullptr)
    {
        if (m_sshPortForward->isForwarding())
            m_sshPortForward->stopForwarding();
    }
    disableControls();
}

void MainWindow::on_closeNotebookButton_clicked()
{
    auto selectedItems = ui->runningTable->selectedItems();

    if (selectedItems.size() > 0)
    {
        auto jobId = selectedItems[0]->text().toInt();
        m_notebookController->cancel(jobId);
    }

    m_notebookController->job_table();
}

void MainWindow::on_openNotebookButton_clicked()
{
    auto selectedItems = ui->runningTable->selectedItems();

    if (selectedItems.size() > 0)
    {
        auto url = selectedItems[3]->text();
        log("Opening URL: " + url);

        auto parts = parseNotebookUrl(url);

        if (parts.token.isEmpty())
        {
            log("No token found in URL");
            return;
        }

        log("Protocol: " + parts.protocol);
        log("Host: " + parts.host);
        log("Port: " + QString::number(parts.port));
        log("Path: " + parts.path);
        log("Token: " + parts.token);

        QUrl localUrl;
        localUrl.setScheme(parts.protocol);
        localUrl.setHost(parts.host);
        localUrl.setPort(8888);
        localUrl.setPath(parts.path);
        localUrl.setQuery("token=" + parts.token);

        m_sshPortForward->startForwarding(8888, "localhost", QUrl(url).port());

        bool success = QDesktopServices::openUrl(localUrl);
        if (!success)
        {
            // Handle error case
            qDebug() << "Failed to open URL";
        }
    }
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (m_sshClient != nullptr)
    {
        m_sshClient->disconnect();
    }

    if (m_sshPortForward != nullptr)
    {
        if (m_sshPortForward->isForwarding())
            m_sshPortForward->stopForwarding();
    }

    event->accept();
}
