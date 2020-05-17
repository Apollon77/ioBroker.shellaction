"use strict";

/*
 *
 *      ioBroker Shell Action Adapter
 *
 *      (c) 2020 bettman66<w.zengel@gmx.de>
 *
 *      MIT License
 *
 */

const utils = require("@iobroker/adapter-core");
const path = require("path");
const helper = require(path.join(__dirname, "lib", "utils.js"));
const { exec } = require("child_process");
const NodeSSH = require("node-ssh");
const CONF_DEVICES = [];

class Shellaction extends utils.Adapter {

    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    constructor(options) {
        super({
            ...options,
            name: "shellaction",
        });
        this.on("ready", this.onReady.bind(this));
        this.on("objectChange", this.onObjectChange.bind(this));
        this.on("stateChange", this.onStateChange.bind(this));
        // this.on("message", this.onMessage.bind(this));
        this.on("unload", this.onUnload.bind(this));
    }

    /**
     * Is called when databases are connected and adapter received configuration.
     */
    async onReady() {
        // Initialize your adapter here
        // Verify the device table contents
        this.setObjectNotExists(this.namespace + ".stdout", {
            type: "state",
            common: {
                name: "Stdout",
                desc: "Command Output",
                type: "string",
                role: "text",
                read: true,
                write: false
            },
            native: {}
        });

        this.setObjectNotExists(this.namespace + ".command", {
            type: "state",
            common: {
                name: "Command",
                desc: "Command Input",
                type: "string",
                role: "text",
                read: true,
                write: true
            },
            native: {}
        });

        if (!helper.isLikeEmpty(this.config.getRemoteDevices)) {
            for (const lpEntry of this.config.getRemoteDevices) {

                let pass = false;

                // Verify name
                let name = lpEntry.deviceName;
                name = helper.cleanStringForState(name);
                if (name.length < 1) {
                    this.log.warn('[Adapter Configuration Error] Given name "' + lpEntry.deviceName + '" is not valid.');
                } else {
                    pass = true;
                }

                // Verify command
                const command = lpEntry.deviceCommand;

                if (command.length < 1) {
                    this.log.warn('[Adapter Configuration Error] Given command "' + lpEntry.deviceCommand + '" is not valid.');
                } else {
                    pass = true;
                }

                // Verify IP address
                let ip = lpEntry.deviceIp;
                if (ip.length < 1) {
                    if (pass) CONF_DEVICES.push({ deviceName: name, deviceIp: "", devicePort: "", loginName: "", loginPassword: "", deviceCommand: command });
                } else {
                    ip = ip.replace(/\s+/g, ""); // remove all white-spaces
                    const checkIp = ip.match(/^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/);
                    if (checkIp == null && ip != "localhost") {
                        this.log.warn('[Adapter Configuration Error] Given IP address "' + lpEntry.deviceIp + '" is not valid.');
                    } else {
                        pass = true;
                    }

                    // Verify Port
                    const port = parseInt(lpEntry.devicePort);
                    if (!helper.isLikeEmpty(port) && (port > 1) && (port <= 65535)) {
                        pass = true;
                    } else {
                        this.log.warn('[Adapter Configuration Error] Given port "' + lpEntry.devicePort + '" is not valid.');
                    }

                    // Verify login
                    const login = lpEntry.loginName;

                    if (login.length < 1) {
                        this.log.warn('[Adapter Configuration Error] Given login "' + lpEntry.loginName + '" is not valid.');
                    } else {
                        pass = true;
                    }

                    const password = lpEntry.loginPassword;
                    pass = true;

                    // Finalize
                    if (pass) CONF_DEVICES.push({ deviceName: name, deviceIp: ip, devicePort: port, loginName: login, loginPassword: password, deviceCommand: command });
                }
            }
        }

        if (CONF_DEVICES.length < 1) this.log.error("[Adapter Configuration Error] No devices configured.");

        for (const lpConfDevice of CONF_DEVICES) {
            const ip = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", lpConfDevice.deviceName, "deviceIp");
            await this.setObjectAsync(lpConfDevice.deviceName, {
                type: "state",
                common: {
                    name: ip + "->" + lpConfDevice.deviceCommand,
                    desc: "",
                    type: "boolean",
                    role: "switch",
                    read: true,
                    write: true
                },
                native: {},
            });
        }

        // in this template all states changes inside the adapters namespace are subscribed
        this.subscribeStates("*");

    }

    /**
     * Is called when adapter shuts down - callback has to be called under any circumstances!
     * @param {() => void} callback
     */
    onUnload(callback) {
        try {
            this.log.info("cleaned everything up...");
            callback();
        } catch (e) {
            callback();
        }
    }

    /**
     * Is called if a subscribed object changes
     * @param {string} id
     * @param {ioBroker.Object | null | undefined} obj
     */
    onObjectChange(id, obj) {
        if (obj) {
            // The object was changed
            this.log.debug(`object ${id} changed: ${JSON.stringify(obj)}`);
        } else {
            // The object was deleted
            this.log.debug(`object ${id} deleted`);
        }
    }

    /**
     * Is called if a subscribed state changes
     * @param {string} id
     * @param {ioBroker.State | null | undefined} state
     */
    onStateChange(id, state) {
        if (state) {
            this.log.debug(`state ${id} changed: ${state.val} (ack = ${state.ack})`);
            if (state.val) {
                // The state was changed
                const name = String(id.split(".").pop());

                if (name == "stdout") {
                    return;
                } else if (name == "command") {
                    try {
                        const jsonContent = JSON.parse(String(state.val));
                        const ip = jsonContent.ip;
                        const command = jsonContent.command;
                        if ((ip == "") || (!ip)) {
                            this.execcommand(name, command);
                        } else {
                            const port = jsonContent.port;
                            const password = jsonContent.password;
                            const user = jsonContent.user;
                            this.execssh(name, ip, port, user, password, command);
                        }
                    } catch (err) {
                        this.log.error(String(state.val) + "->" + err);
                        this.log.error("e.g.->" + '{"user":"pi","password":"raspberry","ip":"192.168.122.27","port":"22","command":"ls"}');
                    }
                } else {
                    const ip = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "deviceIp");
                    const command = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "deviceCommand");
                    if (ip == "") {
                        this.execcommand(name, command);
                    } else {
                        const port = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "devicePort");
                        const password = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "loginPassword");
                        const user = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "loginName");
                        this.execssh(name, ip, port, user, password, command);
                    }
                }
            }
        } else {
            // The state was deleted
            this.log.info(`state ${id} deleted`);
        }
    }

    /**
     * @param {string} name
     * @param {string} command
     */
    execcommand(name, command) {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                this.log.error(`error: ${error.message}`);
                return;
            }
            if (stderr) {
                this.log.error(`stderr: ${stderr}`);
                return;
            }
            this.log.debug(`stdout: ${stdout}`);
            this.setState("stdout", String(stdout), true);
        });
        if (name != "command") this.setState(name, false, true);
    }

    /**
     * @param {string} name
     * @param {string} ip
     * @param {string} port
     * @param {string} user
     * @param {string} password
     * @param {string} command
     */
    execssh(name, ip, port, user, password, command) {
        const ssh = new NodeSSH();
        if (password.includes("id_rsa")) {
            ssh.connect({
                host: ip,
                port: port,
                username: user,
                privateKey: password
            }).then(() => {
                ssh.execCommand(command)
                    .then(result => {
                        this.log.debug(`${result.stdout}`);
                        this.setState("stdout", String(result.stdout), true);
                        ssh.dispose();
                    });
            }).catch(err => {
                this.log.error("Fehler: " + err);
            });
        } else {
            ssh.connect({
                host: ip,
                port: port,
                username: user,
                password: password
            }).then(() => {
                ssh.execCommand(command)
                    .then(result => {
                        this.log.debug(`${result.stdout}`);
                        this.setState("stdout", String(result.stdout), true);
                        ssh.dispose();
                    });
            }).catch(err => {
                this.log.error("Fehler: " + err);
            });
        }
        if (name != "command") this.setState(name, false, true);
    }
}

// @ts-ignore parent is a valid property on module
if (module.parent) {
    // Export the constructor in compact mode
    /**
     * @param {Partial<utils.AdapterOptions>} [options={}]
     */
    module.exports = (options) => new Shellaction(options);
} else {
    // otherwise start the instance directly
    new Shellaction();
}
