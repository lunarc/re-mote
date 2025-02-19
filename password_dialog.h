#pragma once

#include <QCloseEvent>
#include <QDialog>

#include <memory>

QT_BEGIN_NAMESPACE
namespace Ui
{
class PasswordDialog;
}
QT_END_NAMESPACE

class PasswordDialog : public QDialog {
    Q_OBJECT

public:
    PasswordDialog(QWidget *parent = nullptr);
    ~PasswordDialog();

    static bool getConnectionInfo(QWidget *parent, QString &server, QString &username, QString &password,
                           const QString &title = "Connect");

    Ui::PasswordDialog *get_ui();

public slots:

    void on_connectButton_clicked();
    void on_closeButton_clicked();

private:
    Ui::PasswordDialog *ui;
};
