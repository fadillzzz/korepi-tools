const chalk = require('chalk');

const info = chalk.hex('#0bd8e3');
const success = chalk.bold.green;
const error = chalk.bold.red;
const warn = chalk.hex('#FFA500');

function print_header() {
    const title = `    __ __                      _     ______            __    
   / //_____  ________  ____  (_)   /_  ______  ____  / _____
  / ,< / __ \\/ ___/ _ \\/ __ \\/ ______/ / / __ \\/ __ \\/ / ___/
 / /| / /_/ / /  /  __/ /_/ / /_____/ / / /_/ / /_/ / (__  ) 
/_/ |_\\____/_/   \\___/ .___/_/     /_/  \\____/\\____/_/____/  
                    /_/                                        
`;
    console.log(title);
    print_success('Created by @Fad#1234');
}

function print_info(str) {
    console.log(info(getCurrentTime() + ' -> ' + String(str)));
}

function print_success(str) {
    console.log(success(getCurrentTime() + ' -> ' + String(str)));
}

function print_warn(str) {
    console.log(warn(getCurrentTime() + ' -> ' + String(str)));
}

function print_error(str) {
    console.log(error(getCurrentTime() + ' -> ' + String(str)));
}

function getCurrentTime() {
    const now = new Date();
    const time = now.toLocaleTimeString('en-US', { hour12: false });
    return time;
}

module.exports = { print_header, print_info, print_success, print_warn, print_error };