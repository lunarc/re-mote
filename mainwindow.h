#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include <memory>

#include "ssh_client.h"

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

    void on_connectButton_clicked();
    void on_disconnectButton_clicked();
    void on_executeButton_clicked();
    void on_commandEdit_returnPressed();

private:
    Ui::MainWindow *ui;

    std::unique_ptr< SSHClient > m_sshClient;
};
#endif // MAINWINDOW_H
