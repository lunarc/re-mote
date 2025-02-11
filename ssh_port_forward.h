#pragma once

#include "forwarding_channel.h"
#include <QList>
#include <QObject>
#include <QSharedPointer>

class QTcpServer;
class QTcpSocket;
class SSHClient;

class SSHPortForward : public QObject {
    Q_OBJECT

private:
    QSharedPointer< SSHClient > m_client;
    QTcpServer *m_server;
    QList< ForwardingChannel * > m_channels;
    QString m_remoteHost;
    quint16 m_remotePort;
    quint16 m_localPort;
    bool m_isForwarding;

public:
    explicit SSHPortForward(SSHClient *client, QObject *parent = nullptr);
    ~SSHPortForward();

    bool startForwarding(quint16 localPort, const QString &remoteHost, quint16 remotePort);
    void stopForwarding();
    bool isForwarding() const;
    quint16 localPort() const;

signals:
    void error(const QString &message);
    void newConnectionEstablished(const QString &host, quint16 port);
    void connectionClosed();
    void forwardingStarted(quint16 localPort);
    void forwardingStopped();

private slots:
    void handleNewConnection();
    void cleanupChannel(ForwardingChannel *channel);
};
