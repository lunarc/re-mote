#include "job_dialog.h"
#include "ui_job_dialog.h"

JobDialog::JobDialog(QWidget *parent) : QDialog(parent), ui(new Ui::JobDialog)
{
    ui->setupUi(this);
}

JobDialog::~JobDialog()
{
    delete ui;
}

bool JobDialog::getJobInfo(QWidget *parent, QString &name, QString &notebookEnv, QString &wallTime, int &tasksPerNode,
                           const QString &title)
{
    JobDialog dialog(parent);
    dialog.setWindowTitle(title);

    dialog.get_ui()->nameEdit->setText(name);
    dialog.get_ui()->notebookEnvEdit->setText(notebookEnv);
    dialog.get_ui()->wallTimeEdit->setTime(QTime::fromString(wallTime, "hh:mm:ss"));
    dialog.get_ui()->tasksPerNodeEdit->setValue(tasksPerNode);

    if (dialog.exec() == QDialog::Accepted)
    {
        name = dialog.get_ui()->nameEdit->text();
        notebookEnv = dialog.get_ui()->notebookEnvEdit->text();
        wallTime = dialog.get_ui()->wallTimeEdit->text();
        tasksPerNode = dialog.get_ui()->tasksPerNodeEdit->text().toInt();
        return true;
    }
    else
    {
        return false;
    }
}

Ui::JobDialog *JobDialog::get_ui()
{
    return ui;
}

void JobDialog::on_cancelButton_clicked()
{
    reject();
}

void JobDialog::on_okButton_clicked()
{
    accept();
}
