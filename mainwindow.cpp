#include "mainwindow.h"
#include "./ui_mainwindow.h"

MainWindow::MainWindow(QWidget *parent) : QMainWindow(parent), ui(new Ui::MainWindow)
{
    ui->setupUi(this);

    m_sshClient = std::make_unique< SSHClient >(this);

    // Connect signals
    connect(m_sshClient.get(), &SSHClient::connected, this, &MainWindow::onConnected);
    connect(m_sshClient.get(), &SSHClient::commandOutput, this, &MainWindow::handleOutput);
    connect(m_sshClient.get(), &SSHClient::error, this, &MainWindow::handleError);

    // Connect and authenticate
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::onConnected()
{
    ui->statusBar->showMessage("Connected to host");
}

void MainWindow::onDisconnected()
{
    ui->statusBar->showMessage("Disconnected from host");
}

void MainWindow::handleOutput(const QString &output)
{
    ui->textEdit->append(output);
}

void MainWindow::handleError(const QString &error)
{
    ui->statusBar->showMessage(error);
}

void MainWindow::on_connectButton_clicked()
{
    m_sshClient->connectToHost(ui->hostnameEdit->text(), ui->usernameEdit->text());
    m_sshClient->authenticateWithPassword(ui->passwordEdit->text());
    m_sshClient->executeCommand("ls -l");
}

void MainWindow::on_disconnectButton_clicked()
{
    m_sshClient->disconnect();
}
