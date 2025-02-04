// forwardingchannel.cpp
#include "forwarding_channel.h"
#include <QAbstractEventDispatcher>
#include <QEventLoop>
#include <QThread>

ForwardingChannel::ForwardingChannel(ssh_channel channel, QObject *parent)
    : QObject(parent), sshChannel(channel), isRunning(false)
{
}

void ForwardingChannel::start()
{
    isRunning = true;

    // Use non-blocking reads with proper error handling
    while (isRunning)
    {
        char buffer[4096];
        int nbytes = ssh_channel_read_nonblocking(sshChannel, buffer, sizeof(buffer), 0);

        if (nbytes > 0)
        {
            emit dataReceived(QByteArray(buffer, nbytes));
        }
        else if (nbytes == SSH_ERROR)
        {
            emit error(QString("SSH channel read error: %1").arg(ssh_get_error(ssh_channel_get_session(sshChannel))));
            break;
        }
        else if (nbytes == SSH_EOF)
        {
            emit channelClosed();
            break;
        }
        else
        {
            // Use event loop instead of sleep
            QThread::currentThread()->eventDispatcher()->processEvents(QEventLoop::AllEvents);
        }
    }
}

void ForwardingChannel::stop()
{
    isRunning = false;
}

ssh_channel ForwardingChannel::channel() const
{
    return sshChannel;
}

void ForwardingChannel::writeData(const QByteArray &data)
{
    QMutexLocker locker(&writeMutex);

    int written = 0;
    while (written < data.size() && isRunning)
    {
        int result = ssh_channel_write(sshChannel, data.constData() + written, data.size() - written);

        if (result == SSH_ERROR)
        {
            emit error(QString("SSH channel write error: %1").arg(ssh_get_error(ssh_channel_get_session(sshChannel))));
            break;
        }

        written += result;

        // If we couldn't write everything, wait a bit before retrying
        if (written < data.size())
        {
            QThread::msleep(1);
        }
    }
}
