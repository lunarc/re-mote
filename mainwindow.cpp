#include "mainwindow.h"
#include "./ui_mainwindow.h"

#include "ssh_port_forward.h"

#include <iostream>

#include <QInputDialog>

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_sshClient = std::make_unique< SSHClient >(this);

    // Connect signals

    connect(m_sshClient.get(), &SSHClient::connected, this, &MainWindow::onConnected);
    connect(m_sshClient.get(), &SSHClient::disconnected, this, &MainWindow::onDisconnected);
    connect(m_sshClient.get(), &SSHClient::error, this, &MainWindow::onError);
    connect(m_sshClient.get(), &SSHClient::keyboardInteractivePrompt, this, &MainWindow::onKeyboardInteractivePrompt);
    connect(m_sshClient.get(), &SSHClient::authenticationFailed, this, &MainWindow::onAuthenticationFailed);
    connect(m_sshClient.get(), &SSHClient::authenticationSucceeded, this, &MainWindow::onAuthenticationSucceeded);
    connect(m_sshClient.get(), &SSHClient::tunnelEstablished, this, &MainWindow::onTunnelEstablished);
    connect(m_sshClient.get(), &SSHClient::tunnelClosed, this, &MainWindow::onTunnelClosed);
    connect(m_sshClient.get(), &SSHClient::dataReceived, this, &MainWindow::onDataReceived);

    connect(m_sshClient.get(), &SSHClient::commandChannelClosed, this, &MainWindow::onCommandChannelClosed);
    connect(m_sshClient.get(), &SSHClient::commandOutputReceived, this, &MainWindow::onCommandOutputReceived);
    connect(m_sshClient.get(), &SSHClient::commandChannelError, this, &MainWindow::onCommandChannelError);

    disableControls();

    ui->hostnameEdit->setText("172.25.139.172");
    ui->usernameEdit->setText("lindemann");
}

MainWindow::~MainWindow()
{
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

void MainWindow::onCommandChannelClosed(uint64_t channelId)
{
    log("Command channel closed: " + QString::number(channelId));
    // m_sshClient->closeCommandChannel(channelId);
}

void MainWindow::onCommandOutputReceived(uint64_t channelId, const QByteArray &data)
{
    // log("Command output received: " + QString::fromUtf8(data));
    ui->textEdit->append(QString::fromUtf8(data));
}

void MainWindow::onCommandChannelError(uint64_t channelId, const QString &error)
{
    log("Command channel error: " + error);
    // m_sshClient->closeCommandChannel(channelId);
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
}

void MainWindow::on_executeButton_clicked()
{
    m_sshClient->executeCommand(ui->commandEdit->text());
    ui->commandEdit->clear();
}

void MainWindow::on_commandEdit_returnPressed()
{
    m_sshClient->executeCommandAsync(ui->commandEdit->text());
    ui->commandEdit->clear();
}

void MainWindow::on_connectTunnelButton_clicked()
{
    m_sshPortForward = std::make_unique< SSHPortForward >(m_sshClient.get(), this);

    connect(m_sshPortForward.get(), &SSHPortForward::forwardingStarted, this, &MainWindow::onForwardingStarted);
    connect(m_sshPortForward.get(), &SSHPortForward::forwardingStopped, this, &MainWindow::onForwardingStopped);
    connect(m_sshPortForward.get(), &SSHPortForward::error, this, &MainWindow::onForwardError);
    connect(m_sshPortForward.get(), &SSHPortForward::newConnectionEstablished, this,
            &MainWindow::onNewForwardConnectionEstablished);
    connect(m_sshPortForward.get(), &SSHPortForward::connectionClosed, this, &MainWindow::onForwardConnectionClosed);

    m_sshPortForward->startForwarding(8888, "localhost", 8888);
    /*
    SSHClient::TunnelConfig config;
    config.type = SSHClient::TunnelType::Local;
    config.bindAddress = ui->destEdit->text();
    config.bindPort = ui->destPortEdit->text().toUShort();
    config.destAddress = ui->bindEdit->text();
    config.destPort = ui->bindPortEdit->text().toUShort();

    m_sshClient->createTunnel(config);
    */
}

void MainWindow::on_disconnectTunnelButton_clicked()
{
    m_sshPortForward->stopForwarding();
}
