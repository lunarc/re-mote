#pragma once

#include <QObject>
#include <QList>
#include "forwarding_channel.h"

class QTcpServer;
class QTcpSocket;
class SSHClient;

class SSHPortForward : public QObject {
    Q_OBJECT
public:
    explicit SSHPortForward(SSHClient* sshClient, QObject* parent = nullptr);
    ~SSHPortForward();

    bool startForwarding(quint16 localPort, const QString& remoteHost, quint16 remotePort);
    void stopForwarding();

signals:
    void forwardingStarted(quint16 localPort);
    void forwardingStopped();
    void error(const QString& message);
    void newConnectionEstablished(const QString& remoteHost, quint16 remotePort);
    void connectionClosed();

private:
    void handleNewConnection(QTcpSocket* socket, const QString& remoteHost, quint16 remotePort);

    SSHClient* client;
    QTcpServer* tcpServer;
    QList<ForwardingChannel*> channels;
};