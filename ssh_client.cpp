// sshclient.cpp
#include "ssh_client.h"

#include <QDebug>

#include <iostream>

SSHClient::SSHClient(QObject *parent)
    : QObject(parent), m_session(nullptr), m_isAuthenticated(false), m_channelCheckTimer(this),
      m_persistentChannel(nullptr), m_shellChannel(nullptr), m_currentHostname(), m_currentUsername()
{
    m_channelCheckTimer.setInterval(CHANNEL_CHECK_INTERVAL);
    connect(&m_channelCheckTimer, &QTimer::timeout, this, &SSHClient::checkChannels);
}

SSHClient::~SSHClient()
{
    // disconnect();
}

bool SSHClient::connectToHost(const QString &hostname, const QString &username, uint16_t port)
{
    if (m_session)
    {
        disconnect();
    }

    m_currentHostname = hostname;
    m_currentUsername = username;

    initializeSession();

    ssh_options_set(m_session, SSH_OPTIONS_HOST, hostname.toStdString().c_str());
    ssh_options_set(m_session, SSH_OPTIONS_USER, username.toStdString().c_str());
    ssh_options_set(m_session, SSH_OPTIONS_PORT, &port);

    int rc = ssh_connect(m_session);
    if (rc != SSH_OK)
    {
        QString errorMsg = QString("Connection failed: %1").arg(ssh_get_error(m_session));
        emit error(errorMsg);
        cleanupSession();
        return false;
    }

    if (!verifyHostKey())
    {
        emit error("Host key verification failed");
        cleanupSession();
        return false;
    }

    emit connected();
    m_channelCheckTimer.start();
    return true;
}

void SSHClient::disconnect()
{
    m_channelCheckTimer.stop();

    for (auto it = m_activeChannels.begin(); it != m_activeChannels.end(); ++it)
    {
        ssh_channel_close(it.value().channel);
        ssh_channel_free(it.value().channel);
    }
    m_activeChannels.clear();

    if (m_session)
    {
        cleanupSession();
    }

    m_isAuthenticated = false;
    emit disconnected();
}

bool SSHClient::authenticateWithPassword(const QString &password)
{
    if (!m_session || m_isAuthenticated)
        return false;

    int rc = ssh_userauth_password(m_session, nullptr, password.toStdString().c_str());

    m_isAuthenticated = (rc == SSH_AUTH_SUCCESS);

    if (m_isAuthenticated)
        emit authenticationSucceeded();
    else
        emit authenticationFailed();

    return m_isAuthenticated;
}

bool SSHClient::authenticateWithPublicKey(const QString &privateKeyPath, const QString &passphrase)
{
    if (!m_session || m_isAuthenticated)
        return false;

    ssh_key private_key;
    int rc = ssh_pki_import_privkey_file(privateKeyPath.toStdString().c_str(),
                                         passphrase.isEmpty() ? nullptr : passphrase.toStdString().c_str(), nullptr,
                                         nullptr, &private_key);

    if (rc != SSH_OK)
    {
        emit error("Failed to load private key");
        return false;
    }

    rc = ssh_userauth_publickey(m_session, nullptr, private_key);
    ssh_key_free(private_key);

    m_isAuthenticated = (rc == SSH_AUTH_SUCCESS);

    if (m_isAuthenticated)
        emit authenticationSucceeded();
    else
        emit authenticationFailed();

    return m_isAuthenticated;
}

bool SSHClient::authenticateWithKeyboardInteractive()
{
    if (!m_session || m_isAuthenticated)
        return false;

    int rc = ssh_userauth_kbdint(m_session, nullptr, nullptr);

    while (rc == SSH_AUTH_INFO)
    {
        const char *name = ssh_userauth_kbdint_getname(m_session);
        const char *instruction = ssh_userauth_kbdint_getinstruction(m_session);
        int nprompts = ssh_userauth_kbdint_getnprompts(m_session);

        QStringList prompts;
        for (int i = 0; i < nprompts; i++)
        {
            char echo;
            const char *prompt = ssh_userauth_kbdint_getprompt(m_session, i, &echo);
            prompts << QString::fromUtf8(prompt);
        }

        emit keyboardInteractivePrompt(QString::fromUtf8(name), QString::fromUtf8(instruction), prompts);

        // Wait for response through sendKeyboardInteractiveResponse slot
        return true;
    }

    m_isAuthenticated = (rc == SSH_AUTH_SUCCESS);

    if (m_isAuthenticated)
        emit authenticationSucceeded();
    else
        emit authenticationFailed();

    return m_isAuthenticated;
}

void SSHClient::sendKeyboardInteractiveResponse(const QStringList &responses)
{
    if (!m_session)
        return;

    int nprompts = ssh_userauth_kbdint_getnprompts(m_session);
    for (int i = 0; i < nprompts && i < responses.size(); i++)
    {
        ssh_userauth_kbdint_setanswer(m_session, i, responses[i].toStdString().c_str());
    }

    int rc = ssh_userauth_kbdint(m_session, nullptr, nullptr);

    if (rc == SSH_AUTH_INFO)
    {
        // Another round of keyboard-interactive auth needed
        authenticateWithKeyboardInteractive();
    }
    else
    {
        m_isAuthenticated = (rc == SSH_AUTH_SUCCESS);

        if (m_isAuthenticated)
            emit authenticationSucceeded();
        else
            emit authenticationFailed();
    }
}

#ifdef LIBSSH_VERSION_INT
#if LIBSSH_VERSION_INT >= SSH_VERSION_INT(0, 9, 0)
#define HAVE_SSH_CHANNEL_OPEN_REVERSE_FORWARD
#endif
#endif

bool SSHClient::createTunnel(const TunnelConfig &config)
{
    if (!m_session || !m_isAuthenticated)
        return false;

    ssh_channel channel = ssh_channel_new(m_session);
    if (channel == nullptr)
    {
        emit error("Failed to create channel");
        return false;
    }

    int rc;
    if (config.type == TunnelType::Local)
    {
        rc = ssh_channel_open_forward(channel, config.destAddress.toStdString().c_str(), config.destPort,
                                      config.bindAddress.toStdString().c_str(), config.bindPort);
    }
#ifdef HAVE_SSH_CHANNEL_OPEN_REVERSE_FORWARD
    else
    {
        // rc = ssh_channel_open_reverse_forward(channel, config.bindAddress.toStdString().c_str(), config.bindPort,
        //                                       config.destAddress.toStdString().c_str(), config.destPort);
    }
#else
    else
    {
        ssh_channel_free(channel);
        emit error("Reverse forwarding not supported in this version of libssh");
        return false;
    }
#endif

    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        emit error("Failed to establish tunnel");
        return false;
    }

    QString channelKey = QString("%1:%2").arg(config.bindAddress).arg(config.bindPort);

    Channel channelInfo = {channel, config};
    m_activeChannels[channelKey] = channelInfo;

    emit tunnelEstablished(config.bindAddress, config.bindPort);
    return true;
}

void SSHClient::closeTunnel(const QString &bindAddress, uint16_t bindPort)
{
    QString channelKey = QString("%1:%2").arg(bindAddress).arg(bindPort);

    auto it = m_activeChannels.find(channelKey);
    if (it != m_activeChannels.end())
    {
        ssh_channel_close(it.value().channel);
        ssh_channel_free(it.value().channel);
        m_activeChannels.remove(channelKey);

        emit tunnelClosed(bindAddress, bindPort);
    }
}

bool SSHClient::executeCommand(const QString &command)
{
    if (!m_session || !m_isAuthenticated)
        return false;

    ssh_channel channel = ssh_channel_new(m_session);

    if (channel == nullptr)
    {
        emit error("Failed to create channel");
        return false;
    }

    int rc = ssh_channel_open_session(channel);

    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        emit error("Failed to open channel");
        return false;
    }

    rc = ssh_channel_request_exec(channel, command.toStdString().c_str());

    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        emit error("Failed to execute command");
        return false;
    }

    char buffer[CHANNEL_BUFFER_SIZE];
    int nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);

    while (nbytes > 0)
    {
        emit dataReceived(QByteArray(buffer, nbytes));
        nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
    }

    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return true;
}

bool SSHClient::isConnected() const
{
    return m_session && ssh_is_connected(m_session);
}

bool SSHClient::isAuthenticated() const
{
    return m_isAuthenticated;
}

void SSHClient::checkChannels()
{
    if (!m_session)
        return;

    // Check active channels

    for (auto it = m_activeChannels.begin(); it != m_activeChannels.end(); ++it)
    {
        ssh_channel channel = it.value().channel;

        if (ssh_channel_is_closed(channel))
        {
            const TunnelConfig &config = it.value().config;
            closeTunnel(config.bindAddress, config.bindPort);
            continue;
        }

        // Check for incoming data
        char buffer[CHANNEL_BUFFER_SIZE];
        int nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);

        if (nbytes > 0)
        {
            emit dataReceived(QByteArray(buffer, nbytes));
        }
    }

    checkPersistentChannel();
}

void SSHClient::sendData(const QByteArray &data)
{
    if (!m_session || m_activeChannels.isEmpty())
        return;

    // Send to all active channels
    for (const auto &channelInfo : m_activeChannels)
    {
        ssh_channel_write(channelInfo.channel, data.constData(), data.size());
    }
}

bool SSHClient::verifyHostKey()
{
    ssh_key server_key;
    int rc = ssh_get_server_publickey(m_session, &server_key);
    if (rc != SSH_OK)
        return false;

    size_t hash_len;
    unsigned char *hash = nullptr;
    rc = ssh_get_publickey_hash(server_key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hash_len);
    ssh_key_free(server_key);

    if (rc != SSH_OK)
        return false;

    ssh_clean_pubkey_hash(&hash);

    // In a real application, you would verify the hash against known hosts
    // For this example, we'll accept all keys
    return true;
}

void SSHClient::cleanupSession()
{
    if (m_session)
    {
        ssh_disconnect(m_session);
        ssh_free(m_session);
        m_session = nullptr;
    }
}

void SSHClient::initializeSession()
{
    m_session = ssh_new();
    if (!m_session)
    {
        emit error("Failed to create SSH session");
        return;
    }

    // Set some default options
    int verbosity = SSH_LOG_NOLOG;
    ssh_options_set(m_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);

    int timeout = 10; // seconds
    ssh_options_set(m_session, SSH_OPTIONS_TIMEOUT, &timeout);
}

void SSHClient::checkPersistentChannel()
{
    if (!m_persistentChannel || !m_persistentChannel->active)
        return;

    ssh_channel channel = m_persistentChannel->channel;
    bool hasData = false;

    // Check if channel has exited
    if (!m_persistentChannel->hasExited && ssh_channel_is_eof(channel))
    {
        m_persistentChannel->hasExited = true;
        m_persistentChannel->exitStatus = ssh_channel_get_exit_status(channel);
    }

    // Read and filter stdout
    char buffer[CHANNEL_BUFFER_SIZE];
    int nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 0);
    if (nbytes > 0)
    {
        QByteArray filtered = filterPtyOutput(QByteArray(buffer, nbytes));
        if (!filtered.isEmpty())
        {
            emit channelOutputReceived(filtered, false);
        }
        hasData = true;
    }

    // Read and filter stderr if not merging output
    if (!m_persistentChannel->options.mergeOutput)
    {
        nbytes = ssh_channel_read_nonblocking(channel, buffer, sizeof(buffer), 1);
        if (nbytes > 0)
        {
            QByteArray filtered = filterPtyOutput(QByteArray(buffer, nbytes));
            if (!filtered.isEmpty())
            {
                emit channelOutputReceived(filtered, true);
            }
            hasData = true;
        }
    }

    // Close channel if no more data and EOF received
    if (!hasData && m_persistentChannel->hasExited && ssh_channel_is_eof(channel))
    {
        closeCommandChannel();
    }
}

ssh_session SSHClient::session() const
{
    return m_session;
}

bool SSHClient::openCommandChannel(const CommandOptions &options)
{
    if (!m_session || !m_isAuthenticated)
        return false;

    if (m_persistentChannel)
    {
        emit error("Command channel already open");
        return false;
    }

    ssh_channel channel = ssh_channel_new(m_session);
    if (channel == nullptr)
    {
        emit error("Failed to create command channel");
        return false;
    }

    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        emit error("Failed to open command channel");
        return false;
    }

    if (options.ptyEnabled)
    {
        rc = ssh_channel_request_pty_size(channel, options.term.toStdString().c_str(), options.columns, options.rows);
        if (rc != SSH_OK)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            emit error("Failed to request PTY");
            return false;
        }

        // Request shell for interactive session
        rc = ssh_channel_request_shell(channel);
        if (rc != SSH_OK)
        {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            emit error("Failed to request shell");
            return false;
        }
    }

    m_persistentChannel = std::make_unique< PersistentChannel >();
    m_persistentChannel->channel = channel;
    m_persistentChannel->active = true;
    m_persistentChannel->options = options;
    m_persistentChannel->hasExited = false;
    m_persistentChannel->exitStatus = 0;

    emit channelOpened();
    return true;
}

void SSHClient::closeCommandChannel()
{
    if (m_persistentChannel)
    {
        ssh_channel_send_eof(m_persistentChannel->channel);
        ssh_channel_close(m_persistentChannel->channel);
        ssh_channel_free(m_persistentChannel->channel);
        emit channelClosed(m_persistentChannel->exitStatus);
        m_persistentChannel.reset();
    }
}

bool SSHClient::executeInChannel(const QString &command)
{
    if (!m_persistentChannel || !m_persistentChannel->active)
    {
        emit error("No active command channel");
        return false;
    }

    // For PTY-enabled channels, just write the command
    if (m_persistentChannel->options.ptyEnabled)
    {
        QByteArray cmdWithNewline = command.toUtf8() + "\n";
        return writeToChannel(cmdWithNewline);
    }
    else
    {
        // For non-PTY channels, use exec
        int rc = ssh_channel_request_exec(m_persistentChannel->channel, command.toStdString().c_str());
        return rc == SSH_OK;
    }
}

bool SSHClient::writeToChannel(const QByteArray &data)
{
    if (!m_persistentChannel || !m_persistentChannel->active)
    {
        return false;
    }

    int rc = ssh_channel_write(m_persistentChannel->channel, data.constData(), data.size());
    return rc == data.size();
}

bool SSHClient::resizeChannel(int columns, int rows)
{
    if (!m_persistentChannel || !m_persistentChannel->active || !m_persistentChannel->options.ptyEnabled)
    {
        return false;
    }

    int rc = ssh_channel_change_pty_size(m_persistentChannel->channel, columns, rows);
    return rc == SSH_OK;
}

void SSHClient::setPtyFilter(PtyFilterCallback filter)
{
    m_ptyFilter = filter;
}

QByteArray SSHClient::cleanTerminalOutput(const QByteArray &data)
{
    return QByteArray();
}

bool SSHClient::isCommandChannelOpen() const
{
    return m_persistentChannel && m_persistentChannel->active;
}

QByteArray SSHClient::filterPtyOutput(const QByteArray &data)
{
    if (!m_persistentChannel || !m_persistentChannel->options.ptyEnabled)
        return data;

    switch (m_persistentChannel->options.outputMode)
    {
    case PtyOutputMode::Raw:
        return data;

    case PtyOutputMode::StripAll:
        return stripAnsiSequences(data, false);

    case PtyOutputMode::Basic:
        return stripAnsiSequences(data, true);

    case PtyOutputMode::Custom:
        return m_ptyFilter ? m_ptyFilter(data) : data;

    default:
        return data;
    }
}

QByteArray SSHClient::stripAnsiSequences(const QByteArray &data, bool keepBasicFormatting)
{
    QByteArray result;
    result.reserve(data.size());

    enum class State
    {
        Normal,
        Escape,
        CSI,
        OSC
    };
    State state = State::Normal;

    for (int i = 0; i < data.size(); ++i)
    {
        unsigned char c = data[i];

        switch (state)
        {
        case State::Normal:
            if (c == '\x1B') // ESC
                state = State::Escape;
            else if (c == '\a' || c == '\b') // Bell or backspace
                continue;
            else
                result.append(c);
            break;

        case State::Escape:
            if (c == '[')
                state = State::CSI;
            else if (c == ']')
                state = State::OSC;
            else
                state = State::Normal;
            break;

        case State::CSI:
            if (c >= 0x40 && c <= 0x7E) // End of CSI sequence
            {
                if (keepBasicFormatting && c == 'm') // SGR sequence
                {
                    // Keep only color and basic formatting
                    result.append('\x1B');
                    result.append('[');
                    result.append(data.mid(i - (i - 2), i - 1));
                    result.append(c);
                }
                state = State::Normal;
            }
            break;

        case State::OSC:
            // Skip window title and other OSC sequences
            if (c == '\x07' || (c == '\\' && i > 0 && data[i - 1] == '\x1B'))
                state = State::Normal;
            break;
        }
    }

    // Remove initial "0;" if present
    if (result.startsWith("0;"))
        result.remove(0, 2);

    return result;

    return result;
}
