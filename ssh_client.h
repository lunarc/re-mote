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

public slots:
    void sendKeyboardInteractiveResponse(const QStringList &responses);
    void sendData(const QByteArray &data);

private slots:
    void checkChannels();

private:
    struct Channel
    {
        ssh_channel channel;
        TunnelConfig config;
    };

    bool verifyHostKey();
    void cleanupSession();
    void initializeSession();
    bool handleAuthMethod(AuthMethod method);

    ssh_session m_session;
    QMap< QString, Channel > m_activeChannels;
    QTimer m_channelCheckTimer;
    QString m_currentHostname;
    QString m_currentUsername;
    bool m_isAuthenticated;

    static constexpr int CHANNEL_BUFFER_SIZE = 4096;
    static constexpr int CHANNEL_CHECK_INTERVAL = 100; // ms
};
