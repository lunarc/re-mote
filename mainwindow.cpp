#include "mainwindow.h"
#include "./ui_mainwindow.h"

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

    disableControls();
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

void MainWindow::onConnected()
{
    ui->statusBar->showMessage("Connected to host");
}

void MainWindow::onDisconnected()
{
    ui->statusBar->showMessage("Disconnected from host");
    disableControls();
}

void MainWindow::onError(const QString &error)
{
    ui->statusBar->showMessage(error);
}

void MainWindow::onAuthenticationFailed()
{
    ui->statusBar->showMessage("Authentication failed.");
    disableControls();
}

void MainWindow::onAuthenticationSucceeded()
{
    ui->statusBar->showMessage("Authentication succeeded.");
    enableControls();
}

void MainWindow::onKeyboardInteractivePrompt(const QString &name, const QString &instruction,
                                             const QStringList &prompts)
{
    // For this example, we'll just send an empty response
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

void MainWindow::on_connectButton_clicked()
{
    m_sshClient->connectToHost(ui->hostnameEdit->text(), ui->usernameEdit->text());
    // m_sshClient->authenticateWithPassword(ui->passwordEdit->text());
    //  m_sshClient->authenticateWithPublicKey("/path/to/private_key", "passphrase");
    m_sshClient->authenticateWithKeyboardInteractive();

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
    m_sshClient->executeCommand(ui->commandEdit->text());
    ui->commandEdit->clear();
}
