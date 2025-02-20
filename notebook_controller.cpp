#include "notebook_controller.h"

#include <iostream>

NotebookController::NotebookController(SSHClient *sshClient)
    : m_sshClient(sshClient), m_initialised(false), m_command(NotebookCommand::NoCommand)
{
}

NotebookController::~NotebookController()
{
    if (!m_initialised)
        return;

    //    m_sshClient->executeInChannel("quit");
}

void NotebookController::initialise()
{
    if (m_sshClient->isCommandChannelOpen())
    {
        m_command = NotebookCommand::Initialised;
        m_sshClient->executeInChannel("nblaunch");
        m_initialised = true;
    }
}

std::shared_ptr< NotebookController > NotebookController::create(SSHClient *sshClient)
{
    return std::make_shared< NotebookController >(sshClient);
}

bool NotebookController::isInitialised() const
{
    return m_initialised;
}

void NotebookController::submit(QString &name, QString &notebookEnv, QString &wallTime, int tasksPerNode)
{
    if (!m_initialised)
        return;

    m_command = NotebookCommand::Submit;
    m_sshClient->executeInChannel("submit " + name + " " + notebookEnv + " " + wallTime + " " +
                                  QString::number(tasksPerNode));
}

void NotebookController::job_table()
{
    if (!m_initialised)
        return;

    m_command = NotebookCommand::JobTable;
    m_sshClient->executeInChannel("job_table");
}

void NotebookController::cancel(int id)
{
    if (!m_initialised)
        return;

    m_command = NotebookCommand::Cancel;
    m_sshClient->executeInChannel("cancel " + QString::number(id));
}

void NotebookController::cancel_all()
{
    if (!m_initialised)
        return;

    m_command = NotebookCommand::CancelAll;
    m_sshClient->executeInChannel("cancel_all");
}

void NotebookController::setCommand(NotebookCommand command)
{
    m_command = command;
}

NotebookCommand NotebookController::lastCommand() const
{
    return m_command;
}

void NotebookController::parseCommandOutput(const QString &output)
{
    switch (m_command)
    {
    case NotebookCommand::Initialised:
        if (output.contains("Welcome to Jupyter"))
        {
            m_initialised = true;
        }
        break;
    case NotebookCommand::Submit:
        parseSubmit(output);
        break;
    case NotebookCommand::JobTable:
        parseJobTable(output);
        break;
    case NotebookCommand::Cancel:
        if (output.contains("Cancelled"))
        {
            m_command = NotebookCommand::NoCommand;
        }
        break;
    case NotebookCommand::CancelAll:
        if (output.contains("Cancelled all"))
        {
            m_command = NotebookCommand::NoCommand;
        }
        break;
    default:
        break;
    }
}

void NotebookController::parseJobTable(const QString &output)
{
    std::cout << "Parsing job table" << std::endl;

    QStringList lines = output.split('\n');

    bool capture = false;

    for (const QString &line : lines)
    {
        if (line.contains(">>>"))
        {
            std::cout << "Start capturing job table" << std::endl;
            capture = true;
            m_jobs.clear();
            continue;
        }
        else if (line.contains("<<<"))
        {
            std::cout << "Stopping capture of job table" << std::endl;
            capture = false;
            continue;
        }

        if (capture)
        {
            QStringList parts = line.split(';');
            if (parts.size() == 4)
            {
                Job job;
                job.id = parts[0].toInt();
                job.name = parts[1];
                job.status = parts[2];
                job.url = parts[3];

                std::cout << "Job: " << job.id << " " << job.name.toStdString() << " " << job.status.toStdString()
                          << " " << job.url.toStdString() << std::endl;

                m_jobs.append(job);
            }
        }
    }

    emit jobTableUpdated();
}

void NotebookController::parseSubmit(const QString &output)
{
    std::cout << "Parsing job submit" << std::endl;

    QStringList lines = output.split('\n');

    bool capture = false;

    for (const QString &line : lines)
    {
        if (line.contains(">>>"))
        {
            std::cout << "Start capturing job submit" << std::endl;
            capture = true;
            continue;
        }
        else if (line.contains("<<<"))
        {
            std::cout << "Stopping capture job submit" << std::endl;
            capture = false;
            continue;
        }

        if (capture)
        {
            m_lastJobId = line.toInt();
            std::cout << "Job submitted: " << m_lastJobId << std::endl;
            this->job_table();
        }
    }
}

const QVector< Job > &NotebookController::jobs() const
{
    return m_jobs;
}
