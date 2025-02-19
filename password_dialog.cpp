#include "password_dialog.h"
#include "./ui_password_dialog.h"

PasswordDialog::PasswordDialog(QWidget *parent) : QDialog(parent), ui(new Ui::PasswordDialog)
{
    ui->setupUi(this);
}

PasswordDialog::~PasswordDialog()
{
}

bool PasswordDialog::getConnectionInfo(QWidget *parent, QString &server, QString &username, QString &password,
                                       const QString &title)
{
    PasswordDialog dialog(parent);
    dialog.setWindowTitle(title);

    dialog.get_ui()->serverEdit->setText(server);
    dialog.get_ui()->userEdit->setText(username);

    if (dialog.exec() == QDialog::Accepted)
    {
        server = dialog.get_ui()->serverEdit->text();
        username = dialog.get_ui()->userEdit->text();
        password = dialog.get_ui()->passwordEdit->text();
        return true;
    }
    else
    {
        return false;
    }
}

Ui::PasswordDialog *PasswordDialog::get_ui()
{
    return ui;
}

void PasswordDialog::on_connectButton_clicked()
{
    accept();
}

void PasswordDialog::on_closeButton_clicked()
{
    reject();
}
