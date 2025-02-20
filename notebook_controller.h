#pragma once

#include "ssh_client.h"

#include <QObject>
#include <memory>

enum class NotebookCommand
{
    NoCommand,
    Initialised,
    Submit,
    JobTable,
    Cancel,
    CancelAll
};

struct Job
{
    int id;
    QString name;
    QString status;
    QString url;
};

class NotebookController : public QObject {
    Q_OBJECT
private:
    SSHClient *m_sshClient{nullptr};
    bool m_initialised{false};

    int m_lastJobId{-1};

    QVector< Job > m_jobs;

    NotebookCommand m_command{NotebookCommand::NoCommand};

public:
    NotebookController(SSHClient *sshClient);
    ~NotebookController();

    void initialise();

    static std::shared_ptr< NotebookController > create(SSHClient *sshClient);

    bool isInitialised() const;

    void submit(QString &name, QString &notebookEnv, QString &wallTime, int tasksPerNode);
    void job_table();
    void cancel(int id);
    void cancel_all();

    void setCommand(NotebookCommand command);
    NotebookCommand lastCommand() const;

    void parseCommandOutput(const QString &output);
    void parseJobTable(const QString &output);
    void parseSubmit(const QString &output);

    const QVector< Job > &jobs() const;

signals:
    void jobTableUpdated();
};

using NotebookControllerPtr = std::shared_ptr< NotebookController >;
