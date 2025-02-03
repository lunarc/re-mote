#pragma once

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#endif

#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTcpSocket>
#include <libssh/callbacks.h>
#include <libssh/libssh.h>
#include <memory>

class SSHClient : public QObject {
    Q_OBJECT

public:
    explicit SSHClient(QObject *parent = nullptr);
    ~SSHClient();

    bool connectToHost(const QString &hostname, const QString &username, quint16 port = 22);
    bool authenticateWithPassword(const QString &password);
    bool authenticateWithPublicKey(const QString &privateKeyPath);
    bool authenticateWithKeyboardInteractive();
    bool executeCommand(const QString &command);
    void disconnect();

signals:
    void connected();
    void disconnected();
    void error(const QString &errorMessage);
    void commandOutput(const QString &output);
    void authenticationPrompt(const QString &name, const QString &instruction, const QString &prompt, bool echo);

public slots:
    void provideAuthenticationResponse(const QString &response);

private:
    bool verifyKnownHost();
    void handleError();
    static void keyboardInteractiveCallback(const char *name, int name_len, const char *instruction,
                                            int instruction_len, int num_prompts, const char *const *prompts,
                                            char *const *echo, char *const *answers, void *userdata);

    ssh_session session;
    ssh_channel channel;
    bool isConnected;
    bool isAuthenticating;
    QString pendingResponse;
    struct ssh_callbacks_struct callbacks;
};
