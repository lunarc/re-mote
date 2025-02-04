#pragma once

#include <QMainWindow>

#include <memory>

#include "ssh_client.h"
#include "ssh_port_forward.h"

QT_BEGIN_NAMESPACE
namespace Ui
{
class MainWindow;
}
QT_END_NAMESPACE

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

    void disableControls();
    void enableControls();

    void log(const QString &message);

public slots:

    void onConnected();
    void onDisconnected();
    void onError(const QString &message);

    void onAuthenticationFailed();
    void onAuthenticationSucceeded();
    void onKeyboardInteractivePrompt(const QString &name, const QString &instruction, const QStringList &prompts);
    void onTunnelEstablished(const QString &bindAddress, uint16_t bindPort);
    void onTunnelClosed(const QString &bindAddress, uint16_t bindPort);
    void onDataReceived(const QByteArray &data);

    void onForwardingStarted(quint16 localPort);
    void onForwardingStopped();
    void onForwardError(const QString &message);
    void onNewForwardConnectionEstablished(const QString &remoteHost, quint16 remotePort);
    void onForwardConnectionClosed();

    void onCommandChannelClosed(uint64_t channelId);
    void onCommandOutputReceived(uint64_t channelId, const QByteArray &data);
    void onCommandChannelError(uint64_t channelId, const QString &error);

    void on_connectButton_clicked();
    void on_disconnectButton_clicked();
    void on_executeButton_clicked();
    void on_commandEdit_returnPressed();
    void on_connectTunnelButton_clicked();
    void on_disconnectTunnelButton_clicked();

private:
    Ui::MainWindow *ui;

    std::unique_ptr< SSHClient > m_sshClient;
    std::unique_ptr< SSHPortForward > m_sshPortForward;

    uint64_t m_commandChannel = 0;
};
