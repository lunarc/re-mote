// forwardingchannel.h
#pragma once

#include <QMutex>
#include <QObject>
#include <libssh/libssh.h>

// forwardingchannel.h
class ForwardingChannel : public QObject {
    Q_OBJECT
public:
    explicit ForwardingChannel(ssh_channel channel, QObject *parent = nullptr);
    void start();
    void stop();
    void writeData(const QByteArray &data);

    ssh_channel channel() const;

signals:
    void dataReceived(const QByteArray &data);
    void error(const QString &message);
    void channelClosed();

private:
    ssh_channel sshChannel;
    QAtomicInt isRunning;
    QMutex writeMutex;
};
