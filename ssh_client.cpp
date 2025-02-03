#include "ssh_client.h"

#include <QCoreApplication>
#include <QEventLoop>
#include <libssh/callbacks.h>

SSHClient::SSHClient(QObject *parent) : QObject(parent), isConnected(false), isAuthenticating(false)
{
    session = ssh_new();
    if (session == nullptr)
    {
        emit error("Failed to create SSH session");
    }

    // Initialize callback structure
    memset(&callbacks, 0, sizeof(struct ssh_callbacks_struct));
    callbacks.size = sizeof(struct ssh_callbacks_struct);
    callbacks.userdata = this;
}

SSHClient::~SSHClient()
{
    if (isConnected)
    {
        disconnect();
    }
    ssh_free(session);
}

bool SSHClient::authenticateWithKeyboardInteractive()
{
    if (!isConnected)
    {
        emit error("Not connected to host");
        return false;
    }

    isAuthenticating = true;

    // Set up the keyboard-interactive callback
    callbacks.userdata = this;
    callbacks.keyboard_interactive_response_function = &SSHClient::keyboardInteractiveCallback;

    // Set the callback for the session
    int rc = ssh_set_callbacks(session, &callbacks);
    if (rc != SSH_OK)
    {
        handleError();
        isAuthenticating = false;
        return false;
    }

    rc = ssh_userauth_kbdint(session, nullptr, nullptr);
    while (rc == SSH_AUTH_INFO)
    {
        const char *name = ssh_userauth_kbdint_getname(session);
        const char *instruction = ssh_userauth_kbdint_getinstruction(session);
        int nprompts = ssh_userauth_kbdint_getnprompts(session);

        for (int i = 0; i < nprompts; i++)
        {
            char echo;
            const char *prompt = ssh_userauth_kbdint_getprompt(session, i, &echo);
            emit authenticationPrompt(QString::fromUtf8(name ? name : ""),
                                      QString::fromUtf8(instruction ? instruction : ""),
                                      QString::fromUtf8(prompt ? prompt : ""), echo != 0);

            // Wait for response using a manual event loop
            while (pendingResponse.isEmpty() && isAuthenticating)
            {
                QCoreApplication::processEvents(QEventLoop::AllEvents, 100);
            }

            if (!isAuthenticating || pendingResponse.isEmpty())
            {
                isAuthenticating = false;
                return false;
            }

            rc = ssh_userauth_kbdint_setanswer(session, i, pendingResponse.toUtf8().constData());
            if (rc < 0)
            {
                isAuthenticating = false;
                handleError();
                return false;
            }
            pendingResponse.clear();
        }

        rc = ssh_userauth_kbdint(session, nullptr, nullptr);
    }

    isAuthenticating = false;
    return rc == SSH_AUTH_SUCCESS;
}

void SSHClient::provideAuthenticationResponse(const QString &response)
{
    if (isAuthenticating)
    {
        pendingResponse = response;
    }
}

void SSHClient::keyboardInteractiveCallback(const char *name, int name_len, const char *instruction,
                                            int instruction_len, int num_prompts, const char *prompts[], char *echo[],
                                            char *responses[], void *userdata)
{
    SSHClient *client = static_cast< SSHClient * >(userdata);

    for (int i = 0; i < num_prompts; i++)
    {
        client->emit authenticationPrompt(QString::fromUtf8(name, name_len),
                                          QString::fromUtf8(instruction, instruction_len),
                                          QString::fromUtf8(prompts[i]), echo[i] != 0);

        // Wait for response
        while (client->pendingResponse.isEmpty() && client->isAuthenticating)
        {
            QCoreApplication::processEvents();
        }

        if (!client->isAuthenticating)
        {
            break;
        }

        QByteArray response = client->pendingResponse.toUtf8();
        responses[i] = strdup(response.constData());
        client->pendingResponse.clear();
    }
}

bool SSHClient::connectToHost(const QString &hostname, const QString &username, quint16 port)
{
    if (isConnected)
    {
        disconnect();
    }

    ssh_options_set(session, SSH_OPTIONS_HOST, hostname.toStdString().c_str());
    ssh_options_set(session, SSH_OPTIONS_USER, username.toStdString().c_str());
    ssh_options_set(session, SSH_OPTIONS_PORT, &port);

    int rc = ssh_connect(session);
    if (rc != SSH_OK)
    {
        handleError();
        return false;
    }

    if (!verifyKnownHost())
    {
        ssh_disconnect(session);
        return false;
    }

    isConnected = true;
    emit connected();
    return true;
}

bool SSHClient::authenticateWithPassword(const QString &password)
{
    if (!isConnected)
    {
        emit error("Not connected to host");
        return false;
    }

    int rc = ssh_userauth_password(session, nullptr, password.toStdString().c_str());
    if (rc != SSH_AUTH_SUCCESS)
    {
        handleError();
        return false;
    }

    return true;
}

bool SSHClient::authenticateWithPublicKey(const QString &privateKeyPath)
{
    if (!isConnected)
    {
        emit error("Not connected to host");
        return false;
    }

    int rc = ssh_userauth_publickey_auto(session, nullptr, privateKeyPath.toStdString().c_str());
    if (rc != SSH_AUTH_SUCCESS)
    {
        handleError();
        return false;
    }

    return true;
}

bool SSHClient::executeCommand(const QString &command)
{
    if (!isConnected)
    {
        emit error("Not connected to host");
        return false;
    }

    channel = ssh_channel_new(session);
    if (channel == nullptr)
    {
        handleError();
        return false;
    }

    int rc = ssh_channel_open_session(channel);
    if (rc != SSH_OK)
    {
        ssh_channel_free(channel);
        handleError();
        return false;
    }

    rc = ssh_channel_request_exec(channel, command.toStdString().c_str());
    if (rc != SSH_OK)
    {
        ssh_channel_close(channel);
        ssh_channel_free(channel);
        handleError();
        return false;
    }

    char buffer[256];
    int nbytes;

    while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0)
    {
        emit commandOutput(QString::fromUtf8(buffer, nbytes));
    }

    ssh_channel_send_eof(channel);
    ssh_channel_close(channel);
    ssh_channel_free(channel);

    return true;
}

void SSHClient::disconnect()
{
    if (isConnected)
    {
        ssh_disconnect(session);
        isConnected = false;
        emit disconnected();
    }
}

bool SSHClient::verifyKnownHost()
{
    ssh_key server_pubkey;
    int rc = ssh_get_server_publickey(session, &server_pubkey);
    if (rc != SSH_OK)
    {
        handleError();
        return false;
    }

    unsigned char *hash = nullptr;
    size_t hlen;
    rc = ssh_get_publickey_hash(server_pubkey, SSH_PUBLICKEY_HASH_SHA1, &hash, &hlen);
    ssh_key_free(server_pubkey);

    if (rc != SSH_OK)
    {
        handleError();
        return false;
    }

    ssh_clean_pubkey_hash(&hash);
    return true;
}

void SSHClient::handleError()
{
    emit error(QString::fromUtf8(ssh_get_error(session)));
}

void SSHClient::keyboardInteractiveCallback(const char *name, int name_len, const char *instruction,
                                            int instruction_len, int num_prompts, const char *const *prompts,
                                            char *const *echo, char *const *answers, void *userdata)
{
    SSHClient *client = static_cast< SSHClient * >(userdata);

    for (int i = 0; i < num_prompts; i++)
    {
        client->emit authenticationPrompt(QString::fromUtf8(name, name_len),
                                          QString::fromUtf8(instruction, instruction_len),
                                          QString::fromUtf8(prompts[i]), echo[i] != 0);

        // Wait for response
        while (client->pendingResponse.isEmpty() && client->isAuthenticating)
        {
            QCoreApplication::processEvents();
        }

        if (!client->isAuthenticating)
        {
            break;
        }

        QByteArray response = client->pendingResponse.toUtf8();
        responses[i] = strdup(response.constData());
        client->pendingResponse.clear();
    }
}
