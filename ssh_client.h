#pragma once

#include <QByteArray>
#include <QMap>
#include <QObject>
#include <QString>
#include <QTimer>
#include <libssh/libssh.h>
#include <memory>

class SSHClient : public QObject {
    Q_OBJECT

public:
    using PtyFilterCallback = std::function< QByteArray(const QByteArray &) >;

    enum class AuthMethod
    {
        Password,
        PublicKey,
        KeyboardInteractive
    };

    enum class TunnelType
    {
        Local,
        Remote
    };

    struct TunnelConfig
    {
        TunnelType type;
        QString bindAddress;
        uint16_t bindPort;
        QString destAddress;
        uint16_t destPort;
    };

    enum class PtyOutputMode
    {
        Raw,      // No filtering
        StripAll, // Remove all escape sequences
        Basic,    // Keep basic formatting (colors, bold, etc)
        Custom    // Use custom filter function
    };

    struct CommandOptions
    {
        bool mergeOutput = true;
        bool ptyEnabled = false;
        int columns = 80;
        int rows = 24;
        QString term = "xterm";
        PtyOutputMode outputMode = PtyOutputMode::Raw;
    };

    struct PersistentChannel
    {
        ssh_channel channel;
        bool active;
        CommandOptions options;
        bool hasExited;
        int exitStatus;
    };

private:
    static constexpr int CHANNEL_BUFFER_SIZE = 4096;
    static constexpr int CHANNEL_CHECK_INTERVAL = 100; // ms

    struct Channel
    {
        ssh_channel channel;
        TunnelConfig config;
    };

    ssh_session m_session;
    QMap< QString, Channel > m_activeChannels;
    QTimer m_channelCheckTimer;
    QString m_currentHostname;
    QString m_currentUsername;
    bool m_isAuthenticated;
    std::unique_ptr< PersistentChannel > m_persistentChannel;
    ssh_channel m_shellChannel = nullptr;
    PtyFilterCallback m_ptyFilter;

    bool verifyHostKey();
    void cleanupSession();
    void initializeSession();
    void checkPersistentChannel();

    QByteArray filterPtyOutput(const QByteArray &data);
    QByteArray stripAnsiSequences(const QByteArray &data, bool keepBasicFormatting);

public:
    explicit SSHClient(QObject *parent = nullptr);
    ~SSHClient();

    // Connection management
    bool connectToHost(const QString &hostname, const QString &username, uint16_t port = 22);
    void disconnect();

    // Authentication methods
    bool authenticateWithPassword(const QString &password);
    bool authenticateWithPublicKey(const QString &privateKeyPath, const QString &passphrase = QString());
    bool authenticateWithKeyboardInteractive();

    // Tunneling
    bool createTunnel(const TunnelConfig &config);
    void closeTunnel(const QString &bindAddress, uint16_t bindPort);

    // Command execution
    bool executeCommand(const QString &command);

    bool isConnected() const;
    bool isAuthenticated() const;

    ssh_session session() const;

    bool openCommandChannel(const CommandOptions &options = CommandOptions());
    bool isCommandChannelOpen() const;
    void closeCommandChannel();
    bool executeInChannel(const QString &command);
    bool writeToChannel(const QByteArray &data);
    bool resizeChannel(int columns, int rows);

    void setPtyFilter(PtyFilterCallback filter);

    QByteArray cleanTerminalOutput(const QByteArray &data);

signals:
    void connected();
    void disconnected();
    void error(const QString &message);
    void authenticationFailed();
    void authenticationSucceeded();
    void keyboardInteractivePrompt(const QString &name, const QString &instruction, const QStringList &prompts);
    void tunnelEstablished(const QString &bindAddress, uint16_t bindPort);
    void tunnelClosed(const QString &bindAddress, uint16_t bindPort);
    void dataReceived(const QByteArray &data);

    void channelOpened();
    void channelClosed(int exitStatus);
    void channelOutputReceived(const QByteArray &data, bool isStderr);
    void channelError(const QString &error);

public slots:
    void sendKeyboardInteractiveResponse(const QStringList &responses);
    void sendData(const QByteArray &data);

private slots:
    void checkChannels();
};
