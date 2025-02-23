#pragma once

#include <QCloseEvent>
#include <QMainWindow>

#include <memory>

#include "notebook_controller.h"
#include "ssh_client.h"
#include "ssh_port_forward.h"

struct ConnectionSettings
{
    QString host{};
    uint16_t port{22};
    QString username{};
    QString password{};
    QString privateKeyPath{};
    QString passphrase{};
    bool useKeyboardInteractive = false;
};

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

    void onChannelOpened();
    void onChannelClosed(int exitStatus);
    void onChannelOutputReceived(const QByteArray &data, bool isStderr);
    void onChannelError(const QString &error);

    void onJobTableUpdated();

    void on_connectButton_clicked();
    void on_disconnectButton_clicked();
    void on_executeButton_clicked();
    void on_commandEdit_returnPressed();
    void on_connectTunnelButton_clicked();
    void on_disconnectTunnelButton_clicked();
    void on_newNotebookButton_clicked();
    void on_refreshButton_clicked();
    void on_closeButton_clicked();
    void on_closeNotebookButton_clicked();
    void on_openNotebookButton_clicked();

    void closeEvent(QCloseEvent *event) override;

private:
    Ui::MainWindow *ui;

    SSHClient *m_sshClient{nullptr};
    SSHPortForward *m_sshPortForward{nullptr};

    uint64_t m_commandChannel = 0;

    QString m_notebookUrl;

    NotebookControllerPtr m_notebookController;
    ConnectionSettings m_connectionSettings;
};
