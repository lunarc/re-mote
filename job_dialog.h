#ifndef JOB_DIALOG_H
#define JOB_DIALOG_H

#include <QDialog>

namespace Ui
{
class JobDialog;
}

class JobDialog : public QDialog {
    Q_OBJECT

public:
    explicit JobDialog(QWidget *parent = nullptr);
    ~JobDialog();

    static bool getJobInfo(QWidget *parent, QString &name, QString &notebookEnv, QString &wallTime, int &tasksPerNode,
                           const QString &title = "Job information");

    Ui::JobDialog *get_ui();

public slots:

    void on_okButton_clicked();
    void on_cancelButton_clicked();

private:
    Ui::JobDialog *ui;
};

#endif // JOB_DIALOG_H
