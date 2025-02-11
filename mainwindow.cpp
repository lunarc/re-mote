#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include "ssh_port_forward.h"

#include <iostream>

#include <QDesktopServices>
#include <QInputDialog>
#include <QRegularExpression>
#include <QRegularExpressionMatch>
#include <QRegularExpressionMatchIterator>
#include <QUrl>

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent), ui(new Ui::MainWindow), m_sshClient(nullptr), m_sshPortForward(nullptr)
{
    ui->setupUi(this);

    m_sshClient = new SSHClient(this);

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

    disableControls();

    ui->connectTunnelButton->setEnabled(true);
    ui->disconnectTunnelButton->setEnabled(false);

    ui->hostnameEdit->setText("172.25.140.201");
    ui->usernameEdit->setText("lindemann");
}

MainWindow::~MainWindow()
{
    /*
    if (m_sshPortForward != nullptr)
        delete m_sshPortForward;

    if (m_sshClient != nullptr)
        delete m_sshClient;

    */
    delete ui;
}

void MainWindow::disableControls()
{
    ui->connectButton->setEnabled(true);
    ui->disconnectButton->setEnabled(false);
    ui->executeButton->setEnabled(false);
    ui->commandEdit->setEnabled(false);
}

void MainWindow::enableControls()
{
    ui->connectButton->setEnabled(false);
    ui->disconnectButton->setEnabled(true);
    ui->executeButton->setEnabled(true);
    ui->commandEdit->setEnabled(true);
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
    ui->statusBar->showMessage("Authentication succeeded.");
    enableControls();
    log("Authentication succeeded");

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

        m_sshClient->executeInChannel("conda activate numpy-env");
        m_sshClient->executeInChannel("jupyter lab --no-browser");
    }
}

void MainWindow::onKeyboardInteractivePrompt(const QString &name, const QString &instruction,
                                             const QStringList &prompts)
{
    // For this example, we'll just send an empty response
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

    auto urls = extractUrls(receivedString);

    if (urls.size() > 0)
    {
        for (auto &url : urls)
        {
            log("URL: " + QString(url));
            m_notebookUrl = url;
        }

        bool success = QDesktopServices::openUrl(QUrl(m_notebookUrl));
        if (!success)
        {
            // Handle error case
            qDebug() << "Failed to open URL";
        }
        else
        {
            if (m_sshPortForward == nullptr)
            {
                m_sshPortForward = new SSHPortForward(m_sshClient, this);
                connect(m_sshPortForward, &SSHPortForward::forwardingStarted, this, &MainWindow::onForwardingStarted,
                        Qt::QueuedConnection);
                connect(m_sshPortForward, &SSHPortForward::forwardingStopped, this, &MainWindow::onForwardingStopped,
                        Qt::QueuedConnection);
                connect(m_sshPortForward, &SSHPortForward::error, this, &MainWindow::onForwardError,
                        Qt::QueuedConnection);
                connect(m_sshPortForward, &SSHPortForward::newConnectionEstablished, this,
                        &MainWindow::onNewForwardConnectionEstablished, Qt::QueuedConnection);
                connect(m_sshPortForward, &SSHPortForward::connectionClosed, this,
                        &MainWindow::onForwardConnectionClosed, Qt::QueuedConnection);
            }

            m_sshPortForward->startForwarding(8888, "localhost", QUrl(m_notebookUrl).port());

            ui->connectTunnelButton->setEnabled(false);
            ui->disconnectTunnelButton->setEnabled(true);
        }
    }
}

void MainWindow::onChannelError(const QString &error)
{
    log("Command channel error: " + error);
}

void MainWindow::on_connectButton_clicked()
{
    m_sshClient->connectToHost(ui->hostnameEdit->text(), ui->usernameEdit->text());
    // m_sshClient->authenticateWithPassword(ui->passwordEdit->text());
    // m_sshClient->authenticateWithPublicKey("/path/to/private_key", "passphrase");

    log("Trying to authenticate with KeyboardInteractive");
    m_sshClient->authenticateWithKeyboardInteractive();
    log("isAuthenticated: " + QString::number(m_sshClient->isAuthenticated()));

    if (!m_sshClient->isAuthenticated())
    {
        log("Trying to authenticate with Password");
        m_sshClient->authenticateWithPassword(ui->passwordEdit->text());
    }
    else
        log("Already authenticated");

    // m_sshClient->executeCommand("ls -l");
}

void MainWindow::on_disconnectButton_clicked()
{
    m_sshClient->disconnect();

    if (m_sshPortForward != nullptr)
    {
        if (m_sshPortForward->isForwarding())
            m_sshPortForward->stopForwarding();

        ui->connectTunnelButton->setEnabled(true);
        ui->disconnectTunnelButton->setEnabled(false);
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
    if (m_sshPortForward == nullptr)
    {
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
    }

    m_sshPortForward->startForwarding(8888, "localhost", 8888);

    ui->connectTunnelButton->setEnabled(false);
    ui->disconnectTunnelButton->setEnabled(true);
}

void MainWindow::on_disconnectTunnelButton_clicked()
{
    m_sshPortForward->stopForwarding();
    ui->connectTunnelButton->setEnabled(true);
    ui->disconnectTunnelButton->setEnabled(false);
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
