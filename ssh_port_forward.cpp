#include "ssh_port_forward.h"
#include "ssh_client.h"

#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>

SSHPortForward::SSHPortForward(SSHClient *sshClient, QObject *parent)
    : QObject(parent), client(sshClient), tcpServer(nullptr)
{
}

SSHPortForward::~SSHPortForward()
{
    stopForwarding();
}

bool SSHPortForward::startForwarding(quint16 localPort, const QString &remoteHost, quint16 remotePort)
{
    if (!client || !client->isConnected())
    {
        emit error("SSH client not connected");
        return false;
    }

    // Create and start TCP server
    tcpServer = new QTcpServer(this);
    if (!tcpServer->listen(QHostAddress::LocalHost, localPort))
    {
        emit error(QString("Failed to start listening on port %1: %2").arg(localPort).arg(tcpServer->errorString()));
        return false;
    }

    connect(tcpServer, &QTcpServer::newConnection, this, [=]() {
        QTcpSocket *socket = tcpServer->nextPendingConnection();
        handleNewConnection(socket, remoteHost, remotePort);
    });

    emit forwardingStarted(localPort);
    return true;
}

void SSHPortForward::stopForwarding()
{
    if (tcpServer)
    {
        tcpServer->close();
        delete tcpServer;
        tcpServer = nullptr;
    }

    // Clean up any active forwarding channels
    for (auto channel : channels)
    {
        channel->stop();
        ssh_channel_free(channel->channel());
        delete channel;
    }
    channels.clear();

    emit forwardingStopped();
}

void SSHPortForward::handleNewConnection(QTcpSocket *socket, const QString &remoteHost, quint16 remotePort)
{
    socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);

    ssh_channel channel = ssh_channel_new(client->session());
    if (!channel)
    {
        socket->close();
        socket->deleteLater();
        emit error("Failed to create SSH channel");
        return;
    }

    // Set the channel to non-blocking mode
    ssh_channel_set_blocking(channel, 0);

    // First set the channel blocking mode before opening
    ssh_channel_set_blocking(channel, 1);

    if (ssh_channel_open_forward(channel, remoteHost.toUtf8().constData(), remotePort, "localhost",
                                 socket->localPort()) != SSH_OK)
    {
        ssh_channel_free(channel);
        socket->close();
        socket->deleteLater();
        emit error(QString("Failed to open forward channel: %1").arg(ssh_get_error(client->session())));
        return;
    }

    auto forwardChannel = new ForwardingChannel(channel, this);
    channels.append(forwardChannel);

    // Use queued connections for thread safety
    connect(
        forwardChannel, &ForwardingChannel::dataReceived, socket,
        [socket](const QByteArray &data) { socket->write(data); }, Qt::QueuedConnection);

    connect(socket, &QTcpSocket::readyRead, this, [=]() {
        if (socket->bytesAvailable() > 0)
        {
            QByteArray data = socket->readAll();
            QMetaObject::invokeMethod(forwardChannel, [=]() { forwardChannel->writeData(data); }, Qt::QueuedConnection);
        }
    });

    // Handle channel closure
    connect(forwardChannel, &ForwardingChannel::channelClosed, this, [=]() { socket->close(); });

    connect(socket, &QTcpSocket::disconnected, this, [=]() {
        channels.removeOne(forwardChannel);
        ssh_channel_free(channel);
        forwardChannel->deleteLater();
        socket->deleteLater();
        emit connectionClosed();
    });

    // Start forwarding in a new thread
    QThread *thread = new QThread(this);
    forwardChannel->moveToThread(thread);

    connect(thread, &QThread::started, forwardChannel, &ForwardingChannel::start);
    connect(thread, &QThread::finished, thread, &QThread::deleteLater);
    connect(forwardChannel, &ForwardingChannel::channelClosed, thread, &QThread::quit);

    thread->start();

    emit newConnectionEstablished(remoteHost, remotePort);
}
