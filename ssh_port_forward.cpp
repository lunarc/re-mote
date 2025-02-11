#include "ssh_port_forward.h"
#include "ssh_client.h"

#include <QTcpServer>
#include <QTcpSocket>
#include <QThread>

SSHPortForward::SSHPortForward(SSHClient *client, QObject *parent)
    : QObject(parent), m_client(client), m_server(nullptr), m_remotePort(0), m_localPort(0), m_isForwarding(false)
{
    m_server = new QTcpServer(this);
    connect(m_server, &QTcpServer::newConnection, this, &SSHPortForward::handleNewConnection);
}

SSHPortForward::~SSHPortForward()
{
    stopForwarding();
}

bool SSHPortForward::startForwarding(quint16 localPort, const QString &remoteHost, quint16 remotePort)
{
    // Make sure we're fully stopped first
    stopForwarding();

    if (!m_client || !m_client->isConnected() || !m_client->isAuthenticated())
    {
        emit error("SSH client not ready");
        return false;
    }

    // Ensure server is in a clean state
    if (m_server->isListening())
    {
        m_server->close();
    }

    // Store values before attempting to listen
    m_remoteHost = remoteHost;
    m_remotePort = remotePort;

    if (!m_server->listen(QHostAddress::LocalHost, localPort))
    {
        emit error(QString("Failed to start listening on port %1: %2").arg(localPort).arg(m_server->errorString()));
        m_remoteHost.clear();
        m_remotePort = 0;
        return false;
    }

    m_localPort = m_server->serverPort();
    m_isForwarding = true;

    QMetaObject::invokeMethod(
        this, [this]() { emit forwardingStarted(m_localPort); }, Qt::QueuedConnection);

    return true;
}

void SSHPortForward::stopForwarding()
{
    if (!m_isForwarding)
        return;

    // First set flag to prevent new connections
    m_isForwarding = false;

    // Stop listening for new connections
    if (m_server->isListening())
    {
        m_server->close();
    }

    // Close all active channels safely
    QList< ForwardingChannel * > channelsToRemove = m_channels; // Make a copy
    for (auto channel : channelsToRemove)
    {
        if (channel)
        {
            channel->stop();
            channel->deleteLater();
        }
    }
    m_channels.clear();

    // Reset other members
    m_localPort = 0;
    m_remotePort = 0;
    m_remoteHost.clear();

    emit forwardingStopped();
}

bool SSHPortForward::isForwarding() const
{
    return m_isForwarding;
}

quint16 SSHPortForward::localPort() const
{
    return m_localPort;
}

void SSHPortForward::handleNewConnection()
{
    QTcpSocket *socket = m_server->nextPendingConnection();
    if (!socket)
        return;

    // Configure socket for optimal performance
    socket->setSocketOption(QAbstractSocket::LowDelayOption, 1);
    socket->setSocketOption(QAbstractSocket::SendBufferSizeSocketOption, 256 * 1024);
    socket->setSocketOption(QAbstractSocket::ReceiveBufferSizeSocketOption, 256 * 1024);

    ssh_channel channel = ssh_channel_new(m_client->session());
    if (!channel)
    {
        socket->close();
        socket->deleteLater();
        emit error("Failed to create SSH channel");
        return;
    }

    // Keep blocking for initial setup
    ssh_channel_set_blocking(channel, 1);

    int rc = ssh_channel_open_forward(channel, m_remoteHost.toUtf8().constData(), m_remotePort, "localhost",
                                      socket->localPort());
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        socket->close();
        socket->deleteLater();
        emit error(QString("Failed to open forward channel: %1").arg(ssh_get_error(m_client->session())));
        return;
    }

    // Switch to non-blocking for data transfer
    ssh_channel_set_blocking(channel, 0);

    auto forwardChannel = new ForwardingChannel(channel, this);
    m_channels.append(forwardChannel);

    // Connect socket -> channel
    connect(socket, &QTcpSocket::readyRead, this, [socket, forwardChannel]() {
        if (socket->bytesAvailable() > 0)
        {
            forwardChannel->writeData(socket->readAll());
        }
    });

    // Connect channel -> socket
    connect(
        forwardChannel, &ForwardingChannel::dataReceived, socket,
        [socket](const QByteArray &data) { socket->write(data); }, Qt::DirectConnection);

    // Handle closures
    connect(forwardChannel, &ForwardingChannel::channelClosed, socket, &QTcpSocket::close);
    connect(socket, &QTcpSocket::disconnected, this, [this, socket, forwardChannel]() {
        cleanupChannel(forwardChannel);
        socket->deleteLater();
    });

    forwardChannel->start();
    emit newConnectionEstablished(m_remoteHost, m_remotePort);
}

void SSHPortForward::cleanupChannel(ForwardingChannel *channel)
{
    if (!channel)
        return;

    m_channels.removeOne(channel);
    channel->stop();
    channel->deleteLater();
    emit connectionClosed();
}
