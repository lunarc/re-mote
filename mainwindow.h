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

public slots:

    void onConnected();
    void onDisconnected();
    void handleOutput(const QString &output);
    void handleError(const QString &error);

    void on_connectButton_clicked();
    void on_disconnectButton_clicked();

private:
    Ui::MainWindow *ui;

    std::unique_ptr< SSHClient > m_sshClient;
};
#endif // MAINWINDOW_H
