// forwardingchannel.h
#pragma once

#include <QMutex>
#include <QObject>
#include <QTimer>
#include <libssh/libssh.h>

class ForwardingChannel : public QObject {
    Q_OBJECT
private:
    ssh_channel m_channel;
    bool m_active;
    QTimer m_pollTimer;
    static constexpr int BUFFER_SIZE = 32768; // Increased buffer size

    void checkChannel();

public:
    explicit ForwardingChannel(ssh_channel channel, QObject *parent = nullptr);
    ~ForwardingChannel();

    void writeData(const QByteArray &data);
    bool isActive() const
    {
        return m_active && m_channel;
    }

public slots:
    void start();
    void stop();

signals:
    void dataReceived(const QByteArray &data);
    void channelClosed();
};
