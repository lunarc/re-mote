// forwardingchannel.cpp
#include "forwarding_channel.h"
#include <QAbstractEventDispatcher>
#include <QEventLoop>
#include <QThread>
#include <QTimer>

ForwardingChannel::ForwardingChannel(ssh_channel channel, QObject *parent)
    : QObject(parent), m_channel(channel), m_active(false)
{
    m_pollTimer.setInterval(0); // Make as responsive as possible
    connect(&m_pollTimer, &QTimer::timeout, this, &ForwardingChannel::checkChannel);
}

ForwardingChannel::~ForwardingChannel()
{
    stop();
}

void ForwardingChannel::start()
{
    m_active = true;
    m_pollTimer.start();
}

void ForwardingChannel::stop()
{
    m_active = false;
    m_pollTimer.stop();
    emit channelClosed();
}

void ForwardingChannel::writeData(const QByteArray &data)
{
    if (!m_active || !m_channel)
        return;

    int written = 0;
    const char *ptr = data.constData();
    int remaining = data.size();

    while (remaining > 0 && m_active)
    {
        int n = ssh_channel_write(m_channel, ptr + written, remaining);
        if (n == SSH_ERROR)
        {
            stop();
            return;
        }
        if (n <= 0)
        {
            // Would block, try again later
            QTimer::singleShot(0, this, [this, data = data.mid(written)]() { writeData(data); });
            return;
        }
        written += n;
        remaining -= n;
    }
}

void ForwardingChannel::checkChannel()
{
    if (!m_active || !m_channel)
        return;

    // Check if channel is closed
    if (ssh_channel_is_closed(m_channel))
    {
        stop();
        return;
    }

    // Read available data
    char buffer[BUFFER_SIZE];
    int nbytes = ssh_channel_read_nonblocking(m_channel, buffer, sizeof(buffer), 0);

    if (nbytes > 0)
    {
        emit dataReceived(QByteArray(buffer, nbytes));
    }
    else if (nbytes == SSH_ERROR)
    {
        stop();
    }
}
