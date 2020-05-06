"use strict";

/*
 * Created with @iobroker/create-adapter v1.24.2
 **********************************************
 ************ iobroker.shellaction ************
 **********************************************
 */

const utils = require("@iobroker/adapter-core");
const path = require("path");
const helper = require(path.join(__dirname, "lib", "utils.js"));
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
                role: "state",
                read: true,
                write: false
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

                // Verify IP address
                let ip = lpEntry.deviceIp;
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

                // Verify password
                const password = lpEntry.loginPassword;

                if (password.length < 1) {
                    this.log.warn('[Adapter Configuration Error] Given password "' + lpEntry.loginPassword + '" is not valid.');
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

                // Finalize
                if (pass) CONF_DEVICES.push({ deviceName: name, deviceIp: ip, devicePort: port, loginName: login, loginPassword: password, deviceCommand: command });

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
                    role: "state",
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
            if ((state.val) && (!id.includes("stdout"))) {
                // The state was changed
                const name = id.split(".")[id.split(".").length - 1];

                // get IP and port
                const ip = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "deviceIp");
                const port = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "devicePort");
                const password = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "loginPassword");
                const login = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "loginName");
                const command = helper.getConfigValuePerKey(CONF_DEVICES, "deviceName", name, "deviceCommand");

                const ssh = new NodeSSH();
                ssh.connect({
                    host: ip,
                    port: port,
                    username: login,
                    password: password
                }).then(() => {
                    ssh.execCommand(command)
                        .then(result => {
                            this.log.debug(`${result.stdout}`);
                            this.setState("stdout", String(result.stdout), true);
                            ssh.dispose();
                        });
                }).catch(err => {
                    this.log.info("Fehler: " + err);
                });
                this.setState(name, false, true);
            }
        } else {
            // The state was deleted
            this.log.info(`state ${id} deleted`);
        }
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