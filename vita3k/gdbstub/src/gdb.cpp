#include <memory>

// Vita3K emulator project
// Copyright (C) 2025 Vita3K team
//
// This program is free software; you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation; either version 2 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with this program; if not, write to the Free Software Foundation, Inc.,
// 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

#include <emuenv/state.h>
#include <util/bit_cast.h>
#include <util/log.h>

#include <gdbstub/functions.h>
#include <gdbstub/state.h>

#include <cpu/functions.h>

#include <kernel/state.h>
#include <mem/state.h>
#include <sstream>

// Sockets
#ifdef _WIN32
#include <winsock.h>
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#define LOG_GDB_LEVEL 2

#if LOG_GDB_LEVEL >= 1
#define LOG_GDB LOG_INFO
#else
#define LOG_GDB(a, ...)
#endif

#if LOG_GDB_LEVEL >= 2
#define LOG_GDB_DEBUG LOG_INFO
#else
#define LOG_GDB_DEBUG(a, ...)
#endif

// Credit to jfhs for their GDB stub for RPCS3 which this stub is based on.

typedef char PacketData[1200];

struct PacketCommand {
    char *data{};
    int64_t length = -1;

    int64_t begin_index = -1;
    int64_t end_index = -1;
    int64_t content_length = -1;

    char *content_start{};
    char *checksum_start{};

    uint8_t checksum = 0;

    bool is_valid = false;
};

typedef std::function<std::string(EmuEnvState &state, PacketCommand &command)> PacketFunction;

struct PacketFunctionBundle {
    std::string_view name;
    PacketFunction function;
};

static std::string content_string(PacketCommand &command) {
    return std::string(command.content_start, static_cast<unsigned long>(command.content_length));
}

// Hexes
static std::string be_hex(uint32_t value) {
    return fmt::format("{:0>8x}", htonl(value));
}

static std::string to_hex(uint32_t value) {
    return fmt::format("{:0>8x}", value);
}

static std::string to_hex(SceUID value) {
    return fmt::format("{:0>8x}", value);
}

static uint32_t parse_hex(const std::string &hex) {
    return static_cast<uint32_t>(std::strtoul(hex.c_str(), nullptr, 16));
}

static uint8_t make_checksum(const char *data, int64_t length) {
    size_t sum = 0;

    for (int64_t a = 0; a < length; a++) {
        sum += data[a];
    }

    return static_cast<uint8_t>(sum % 256);
}

static PacketCommand parse_command(char *data, int64_t length) {
    PacketCommand command = {};

    command.data = data;
    command.length = length;

    // TODO: Use std::find() to find packet begin and end.
    if (length > 1)
        command.begin_index = 1;
    for (int64_t a = 0; a < length; a++) {
        if (data[a] == '#')
            command.end_index = a;
    }

    command.is_valid = command.begin_index != -1 && command.end_index != -1
        && command.end_index > command.begin_index && command.end_index + 2 < length;
    if (!command.is_valid)
        return command;

    command.content_start = command.data + command.begin_index;
    command.content_length = command.end_index - command.begin_index;

    command.checksum_start = command.data + command.end_index + 1;
    command.checksum = static_cast<uint8_t>(parse_hex(std::string(command.checksum_start, 2)));

    command.is_valid = make_checksum(command.content_start, command.content_length) == command.checksum;
    if (!command.is_valid)
        return command;

    return command;
}

static int64_t server_reply(GDBState &state, const char *data, int64_t length) {
    uint8_t checksum = make_checksum(data, length);
    std::string packet_data = fmt::format("${}#{:0>2x}", std::string(data, length), checksum);
    return send(state.client_socket, &packet_data[0], packet_data.size(), 0);
}

static int64_t server_reply(GDBState &state, const char *text) {
    return server_reply(state, text, strlen(text));
}

static int64_t server_ack(GDBState &state, char ack = '+') {
    return send(state.client_socket, &ack, 1, 0);
}

static std::string cmd_supported(EmuEnvState &state, PacketCommand &command) {
    return "multiprocess-;swbreak+;hwbreak-;qRelocInsn-;fork-events-;vfork-events-;"
           "exec-events-;vContSupported+;QThreadEvents-;no-resumed-;xmlRegisters=arm";
}

static std::string cmd_reply_empty(EmuEnvState &state, PacketCommand &command) {
    return "";
}

// This function is not thread safe
static SceUID select_thread(EmuEnvState &state, int thread_id) {
    if (thread_id == 0) {
        if (state.kernel.threads.empty())
            return -1;
        return state.kernel.threads.begin()->first;
    }
    return thread_id;
}

static std::string cmd_set_current_thread(EmuEnvState &state, PacketCommand &command) {
    const auto guard = std::lock_guard(state.kernel.mutex);
    int32_t thread_id = parse_hex(std::string(
        command.content_start + 2, static_cast<unsigned long>(command.content_length - 2)));

    switch (command.content_start[1]) {
    case 'c':
        LOG_GDB("GDB Server Deprecated Continue Option 'c'");
        // state.gdb.current_continue_thread = select_thread(state, thread_id);
        break;
    case 'g':
        state.gdb.current_thread = select_thread(state, thread_id);
        break;
    default:
        LOG_GDB("GDB Server Unknown Set Current Thread OP. {}", command.content_start[1]);
        break;
    }

    return "OK";
}

static std::string cmd_get_current_thread(EmuEnvState &state, PacketCommand &command) {
    return "QC" + to_hex(state.gdb.current_thread);
}

static uint32_t fetch_reg(CPUState &state, uint32_t reg) {
    if (reg <= 12) {
        return read_reg(state, reg);
    }

    if (reg == 13)
        return read_sp(state);
    if (reg == 14)
        return read_lr(state);
    if (reg == 15)
        return read_pc(state);

    if (reg <= 23) {
        float value = read_float_reg(state, reg - 16);
        return std::bit_cast<uint32_t>(value);
    }

    if (reg == 24)
        return read_fpscr(state);
    if (reg == 25)
        return read_cpsr(state);

    LOG_GDB("GDB Server Queried Invalid Register {}", reg);
    return 0;
}

static void modify_reg(CPUState &state, uint32_t reg, uint32_t value) {
    if (reg <= 12) {
        write_reg(state, reg, value);
        return;
    }

    if (reg == 13) {
        write_sp(state, value);
        return;
    }
    if (reg == 14) {
        write_lr(state, value);
        return;
    }
    if (reg == 15) {
        write_pc(state, value);
        return;
    }

    if (reg <= 23) {
        write_float_reg(state, reg - 16, std::bit_cast<float>(value));
        return;
    }

    if (reg == 24) {
        write_fpscr(state, value);
        return;
    }
    if (reg == 25) {
        write_cpsr(state, value);
        return;
    }

    LOG_GDB("GDB Server Modified Invalid Register {}", reg);
}

static std::string cmd_read_registers(EmuEnvState &state, PacketCommand &command) {
    const auto guard = std::lock_guard(state.kernel.mutex);
    if (state.gdb.current_thread == -1
        || !state.kernel.threads.contains(state.gdb.current_thread))
        return "E00";

    CPUState &cpu = *state.kernel.threads[state.gdb.current_thread]->cpu.get();

    std::string str;
    str.reserve(16 * 8);

    for (uint32_t a = 0; a < 16; a++) {
        str += be_hex(fetch_reg(cpu, a));
    }

    return str;
}

static std::string cmd_write_registers(EmuEnvState &state, PacketCommand &command) {
    const auto guard = std::lock_guard(state.kernel.mutex);
    if (state.gdb.current_thread == -1
        || !state.kernel.threads.contains(state.gdb.current_thread))
        return "E00";

    CPUState &cpu = *state.kernel.threads[state.gdb.current_thread]->cpu.get();

    const std::string content = content_string(command).substr(1);

    for (uint32_t a = 0; a < content.size() / 8; a++) {
        uint32_t value = parse_hex(content.substr(a * 8, 8));
        modify_reg(cpu, a, value);
    }

    return "OK";
}

static std::string cmd_read_register(EmuEnvState &state, PacketCommand &command) {
    const auto guard = std::lock_guard(state.kernel.mutex);
    if (state.gdb.current_thread == -1
        || !state.kernel.threads.contains(state.gdb.current_thread))
        return "E00";

    CPUState &cpu = *state.kernel.threads[state.gdb.current_thread]->cpu.get();

    const std::string content = content_string(command);
    uint32_t reg = parse_hex(content.substr(1, content.size() - 1));

    return be_hex(fetch_reg(cpu, reg));
}

static std::string cmd_write_register(EmuEnvState &state, PacketCommand &command) {
    const auto guard = std::lock_guard(state.kernel.mutex);
    if (state.gdb.current_thread == -1
        || !state.kernel.threads.contains(state.gdb.current_thread))
        return "E00";

    CPUState &cpu = *state.kernel.threads[state.gdb.current_thread]->cpu.get();

    const std::string content = content_string(command);
    size_t equal_index = content.find('=');
    uint32_t reg = parse_hex(content.substr(1, equal_index - 1));
    uint32_t value = parse_hex(content.substr(equal_index + 1));
    modify_reg(cpu, reg, value);

    return "OK";
}

static bool check_memory_region(Address address, Address length, MemState &mem) {
    if (!address) {
        return false;
    }

    Address it = address;
    bool valid = true;
    for (; it < address + length; it += mem.page_size) {
        if (!is_valid_addr(mem, it)) {
            valid = false;
            break;
        }
    }
    return valid;
}

static std::string cmd_read_memory(EmuEnvState &state, PacketCommand &command) {
    const std::string content = content_string(command);
    const size_t pos = content.find(',');

    const std::string first = content.substr(1, pos - 1);
    const std::string second = content.substr(pos + 1);
    const uint32_t address = parse_hex(first);
    const uint32_t length = parse_hex(second);

    const Address guest_end = static_cast<Address>(address + length);

    if (!is_valid_guest_addr_range(state.mem, address, guest_end)) {
        LOG_ERROR("GDB Server attempted to read invalid memory range: 0x{:08X} - 0x{:08X}", address, guest_end);
        return "EAA";
    }

    if (!check_memory_region(address, length, state.mem))
        return "EAA";

    std::string str;
    str.reserve(length * 2);

    for (uint32_t a = 0; a < length; a++) {
        fmt::format_to(std::back_inserter(str), "{:02x}", *Ptr<uint8_t>(address + a).get(state.mem));
    }

    return str;
}

static std::string cmd_write_memory(EmuEnvState &state, PacketCommand &command) {
    const std::string content = content_string(command);
    const size_t pos_first = content.find(',');
    const size_t pos_second = content.find(':');

    const std::string first = content.substr(1, pos_first - 1);
    const std::string second = content.substr(pos_first + 1, pos_second - pos_first);
    const uint32_t address = parse_hex(first);
    const uint32_t length = parse_hex(second);
    const std::string hex_data = content.substr(pos_second + 1);

    if (!check_memory_region(address, length, state.mem))
        return "EAA";

    for (uint32_t a = 0; a < length; a++) {
        *Ptr<uint8_t>(address + a).get_guest(state.mem) = static_cast<uint8_t>(parse_hex(hex_data.substr(a * 2, 2)));
    }

    return "OK";
}

// server_next() might not be able to tell the difference between the end of the packet ($) and 0x24 ($).
// Thus, cmd_write_binary is disabled.
static std::string cmd_write_binary(EmuEnvState &state, PacketCommand &command) {
    const std::string content = content_string(command);
    const size_t pos_first = content.find(',');
    const size_t pos_second = content.find(':');

    const std::string first = content.substr(1, pos_first - 1);
    const std::string second = content.substr(pos_first + 1, pos_second - pos_first);
    const uint32_t address = parse_hex(first);
    const uint32_t length = parse_hex(second);
    const char *data = command.content_start + pos_second + 1;

    if (!check_memory_region(address, length, state.mem))
        return "EAA";

    for (uint32_t a = 0; a < length; a++) {
        *Ptr<uint8_t>(address + a).get_guest(state.mem) = data[a];
    }

    return "OK";
}

static std::string cmd_detach(EmuEnvState &state, PacketCommand &command) { return "OK"; }

static std::string cmd_continue(EmuEnvState &state, PacketCommand &command) {
    const std::string content = content_string(command);
    constexpr auto watch_delay = std::chrono::milliseconds(100);

    uint64_t index = 5;
    uint64_t next = 0;
    do {
        next = content.find(';', index + 1);
        std::string text = content.substr(index + 1, next - index - 1);

        const char cmd = text[0];
        switch (cmd) {
        case 'c':
        case 'C':
        case 's':
        case 'S': {
            bool step = cmd == 's' || cmd == 'S';

            // inferior_thread is the thread that triggered breakpoint before
            // step or run that thread

            if (state.gdb.inferior_thread != 0) {
                const auto guard = std::lock_guard(state.kernel.mutex);
                auto thread = state.kernel.threads[state.gdb.inferior_thread];
                auto thread_lock = std::unique_lock(thread->mutex);
                thread->resume(step);
                if (step) {
                    // Wait until it finish stepping
                    // TODO if that thread waits for sync primitive, dead lock.
                    thread->status_cond.wait(thread_lock, [&]() { return thread->status == ThreadStatus::suspend; });
                }
            }

            if (!step) {
                // resume the world
                {
                    auto lock = std::unique_lock(state.kernel.mutex);
                    for (const auto &pair : state.kernel.threads) {
                        auto &thread = pair.second;
                        if (thread->status == ThreadStatus::suspend) {
                            lock.unlock();
                            thread->resume();
                            lock.lock();

                            thread->status_cond.wait(lock, [&]() { return thread->status != ThreadStatus::suspend; });
                        }
                    }
                }
                // wait until some threads trigger breakpoint
                bool did_break = false;
                while (!did_break) {
                    auto lock = std::unique_lock(state.kernel.mutex);

                    if (state.gdb.server_die)
                        return "";
                    for (const auto &[id, thread] : state.kernel.threads) {
                        const auto thread_guard = std::lock_guard(thread->mutex);
                        if (thread->status == ThreadStatus::suspend && hit_breakpoint(*thread->cpu)) {
                            state.gdb.inferior_thread = id;
                            did_break = true;
                            break;
                        }
                    }

                    lock.unlock();

                    std::this_thread::sleep_for(std::chrono::milliseconds(watch_delay));
                }

                auto thread = state.kernel.get_thread(state.gdb.inferior_thread);
                LOG_INFO("GDB Breakpoint trigger (thread name: {}, thread_id: {})", thread->name, thread->id);
                LOG_INFO("PC: {} LR: {}", read_pc(*thread->cpu), read_lr(*thread->cpu));
                LOG_INFO("{}", thread->log_stack_traceback());

                // stop the world
                {
                    auto lock = std::unique_lock(state.kernel.mutex);
                    for (const auto &pair : state.kernel.threads) {
                        auto thread = pair.second;
                        if (thread->status == ThreadStatus::run) {
                            thread->suspend();
                            thread->status_cond.wait(lock, [=]() { return thread->status == ThreadStatus::suspend || thread->status == ThreadStatus::dormant; });
                        }
                    }
                }
            }

            state.gdb.current_thread = state.gdb.inferior_thread;
            return "S05";
        }
        default:
            LOG_GDB("Unsupported vCont command '{}'", cmd);
            break;
        }

        index = next;
    } while (next != std::string::npos);

    return "";
}

static std::string cmd_continue_supported(EmuEnvState &state, PacketCommand &command) {
    return "vCont;c;C;s;S;t;r";
}

static std::string cmd_thread_alive(EmuEnvState &state, PacketCommand &command) {
    const auto guard = std::lock_guard(state.kernel.mutex);
    const std::string content = content_string(command);
    const int32_t thread_id = parse_hex(content.substr(1));

    // Assuming a thread is removed from the map when it closes or is killed.
    if (state.kernel.threads.contains(thread_id))
        return "OK";

    return "E00";
}

static std::string cmd_kill(EmuEnvState &state, PacketCommand &command) {
    return "OK";
}

static std::string cmd_die(EmuEnvState &state, PacketCommand &command) {
    state.gdb.server_die = true;
    return "";
}

static std::string cmd_attached(EmuEnvState &state, PacketCommand &command) { return "1"; }

static std::string cmd_thread_status(EmuEnvState &state, PacketCommand &command) { return "T0"; }

static std::string cmd_reason(EmuEnvState &state, PacketCommand &command) { return "S05"; }

static std::string cmd_get_first_thread(EmuEnvState &state, PacketCommand &command) {
    const auto guard = std::lock_guard(state.kernel.mutex);
    state.gdb.thread_info_index = 0;

    return 'm' + to_hex(state.kernel.threads.begin()->first);
}

static std::string cmd_get_next_thread(EmuEnvState &state, PacketCommand &command) {
    const auto guard = std::lock_guard(state.kernel.mutex);
    std::string str;

    ++state.gdb.thread_info_index;
    if (state.gdb.thread_info_index == state.kernel.threads.size()) {
        str += 'l';
    } else {
        auto iter = state.kernel.threads.begin();
        std::advance(iter, state.gdb.thread_info_index);

        str += 'm';
        str += to_hex(iter->first);
    }

    return str;
}

static std::string cmd_add_breakpoint(EmuEnvState &state, PacketCommand &command) {
    const std::string content = content_string(command);

    const uint64_t first = content.find(',');
    const uint64_t second = content.find(',', first + 1);
    const uint32_t type = static_cast<uint32_t>(std::stol(content.substr(1, first - 1)));
    const uint32_t address = parse_hex(content.substr(first + 1, second - 1 - first));
    const uint32_t kind = static_cast<uint32_t>(std::stol(content.substr(second + 1, content.size() - second - 1)));

    if (!is_valid_guest_addr(state.mem, address)) {
        uintptr_t host_addr = get_host_ptr(state.mem, address);
        LOG_GDB("GDB Server attempted to add breakpoint at guest address {} ({}, {}). Maps to host 0x{:016X} which is invalid", log_hex(address), type, kind, host_addr);
        return "EAA";
    }

    LOG_GDB("GDB Server New Breakpoint at {} ({}, {}).", log_hex(address), type, kind);

    // kind is 2 if it's thumb mode
    // https://sourceware.org/gdb/current/onlinedocs/gdb/ARM-Breakpoint-Kinds.html#ARM-Breakpoint-Kinds
    state.kernel.debugger.add_breakpoint(state.mem, address, kind == 2);

    return "OK";
}

static std::string cmd_remove_breakpoint(EmuEnvState &state, PacketCommand &command) {
    const std::string content = content_string(command);

    const uint64_t first = content.find(',');
    const uint64_t second = content.find(',', first + 1);
    const uint32_t type = static_cast<uint32_t>(std::stol(content.substr(1, first - 1)));
    const uint32_t address = parse_hex(content.substr(first + 1, second - 1 - first));
    const uint32_t kind = static_cast<uint32_t>(std::stol(content.substr(second + 1, content.size() - second - 1)));

    if (!is_valid_guest_addr(state.mem, address)) {
        LOG_GDB("GDB Server attempted to remove breakpoint at {} ({}, {}). INVALID ADDRESS!", log_hex(address), type, kind);
        return "EAA";
    }

    LOG_GDB("GDB Server Removed Breakpoint at {} ({}, {}).", log_hex(address), type, kind);
    state.kernel.debugger.remove_breakpoint(state.mem, address);

    return "OK";
}

static std::string cmd_deprecated(EmuEnvState &state, PacketCommand &command) {
    LOG_GDB("GDB Server: Deprecated Packet. {}", content_string(command));

    return "";
}

static std::string cmd_unimplemented(EmuEnvState &state, PacketCommand &command) {
    LOG_GDB("GDB Server: Unimplemented Packet. {}", content_string(command));

    return "";
}

const static PacketFunctionBundle functions[] = {
    // General
    { "!", cmd_unimplemented },
    { "?", cmd_reason },
    { "H", cmd_set_current_thread },
    { "T", cmd_thread_alive },
    { "i", cmd_unimplemented },
    { "I", cmd_unimplemented },
    { "A", cmd_unimplemented },
    { "bc", cmd_unimplemented },
    { "bs", cmd_unimplemented },
    { "t", cmd_unimplemented },

    // Read/Write
    { "p", cmd_read_register },
    { "P", cmd_write_register },
    { "g", cmd_read_registers },
    { "G", cmd_write_registers },
    { "m", cmd_read_memory },
    { "M", cmd_write_memory },
    { "X", cmd_unimplemented }, // change cmd_unimplemented to cmd_write_binary to enable binary downloading

    // Query Packets
    { "qfThreadInfo", cmd_get_first_thread },
    { "qsThreadInfo", cmd_get_next_thread },
    { "qSupported", cmd_supported },
    { "qAttached", cmd_attached },
    { "qTStatus", cmd_thread_status },
    { "qC", cmd_get_current_thread },
    { "q", cmd_unimplemented },
    { "Q", cmd_unimplemented },

    // Shutdown
    { "d", cmd_unimplemented },
    { "r", cmd_unimplemented },
    { "R", cmd_unimplemented },
    { "k", cmd_die },

    // Control Packets
    { "vCont?", cmd_continue_supported },
    { "vCont", cmd_continue },
    { "vKill", cmd_kill },
    { "vMustReplyEmpty", cmd_reply_empty },
    { "v", cmd_unimplemented },

    // Breakpoints
    { "z", cmd_remove_breakpoint },
    { "Z", cmd_add_breakpoint },

    // Deprecated
    { "b", cmd_deprecated },
    { "B", cmd_deprecated },
    { "c", cmd_deprecated },
    { "C", cmd_deprecated },
    { "s", cmd_deprecated },
    { "S", cmd_deprecated },
};

static bool command_begins_with(PacketCommand &command, const std::string_view small_str) {
    // If the command's content is shorter than small_str, it can't match
    if (static_cast<size_t>(command.content_length) < small_str.size())
        return false;

    return std::memcmp(command.content_start, small_str.data(), small_str.size()) == 0;
}

static int64_t server_next(EmuEnvState &state) {
    static std::vector<char> recv_buffer;

    // Wait for the server to close or a packet to be received.
    fd_set readSet;
    timeval timeout = { 1, 0 };
    do {
        readSet = { 0 };
        FD_SET(state.gdb.client_socket, &readSet);
    } while (select(state.gdb.client_socket + 1, &readSet, nullptr, nullptr, &timeout) < 1 && !state.gdb.server_die);
    if (state.gdb.server_die)
        return -1;

    char temp[1024];
    const int64_t length = recv(state.gdb.client_socket, temp, sizeof(temp), 0);
    if (length <= 0) {
        LOG_GDB("GDB Server Connection Closed");
        return -1;
    }
    recv_buffer.insert(recv_buffer.end(), temp, temp + length);

    std::size_t pos = 0;
    while (pos < recv_buffer.size()) {
        char c = recv_buffer[pos];
        if (c == '+') {
            pos += 1;
            continue; // Cool.
        }
        else if (c == '-') {
            LOG_GDB("GDB Server Transmission Error. {}", std::string(recv_buffer.data(), recv_buffer.size()));
            server_reply(state.gdb, state.gdb.last_reply.c_str());
            pos += 1;
            continue;
        }
        else if (c == '$') {
            // Find the matching '#' which denotes the end of the packet plus the 2 checksum digits after
            auto hash_index = std::string::npos;
            for (std::size_t i = pos + 1; i + 2 < recv_buffer.size(); i++) {
                if (recv_buffer[i] == '#') {
                    hash_index = i;
                    break;
                }
            }
            if (hash_index == std::string::npos) {
                // We haven't received the full packet yet
                break;
            }
            if (hash_index + 2 >= recv_buffer.size()) {
                // Not enough data for full packet, missing checksum bytes
                break;
            }

            server_ack(state.gdb, '+');

            std::size_t packet_len = (hash_index + 3) - pos; // from '$' to "#xx"
            std::string packet_data(&recv_buffer[pos], packet_len);
            PacketCommand command = parse_command(&recv_buffer[pos], packet_len);
            if (command.is_valid) {
                bool found_command = false;
                for (const auto &function : functions) {
                    if (command_begins_with(command, function.name)) {
                        found_command = true;
                        LOG_GDB("GDB Server Recognized Command as {}. {}", function.name,
                            std::string(command.content_start, command.content_length));
                        state.gdb.last_reply = function.function(state, command);
                        if (state.gdb.server_die)
                            break;
                        server_reply(state.gdb, state.gdb.last_reply.c_str());
                        break;
                    }
                }
                if (!found_command) {
                    LOG_GDB("GDB Server Unrecognized Command. {}", std::string(command.content_start, command.content_length));
                    state.gdb.last_reply = "";
                    server_reply(state.gdb, state.gdb.last_reply.c_str());
                }
            } else {
                server_ack(state.gdb, '-');

                LOG_GDB("GDB Server Invalid Command. {}", packet_data);
            }

            pos += packet_len;
        } else {
            // Not '+', '-' or '$', Possibly leftover or partial data? We'll skip it
            LOG_GDB("Skipping unexpected char '{}' at pos {}", c, pos);
            pos += 1;
        }
    }

    if (pos > 0) {
        recv_buffer.erase(recv_buffer.begin(), recv_buffer.begin() + pos);
    }

    return length;
}

static void server_listen(EmuEnvState &state) {
    state.gdb.client_socket = accept(state.gdb.listen_socket, nullptr, nullptr);

    if (state.gdb.client_socket == -1) {
        LOG_GDB("GDB Server Failed: Could not accept socket.");
        return;
    }

    LOG_INFO("GDB Server Received Connection");

    int64_t status;

    do {
        status = server_next(state);
    } while (status >= 0 && !state.gdb.server_die);

    server_close(state);
}

void server_open(EmuEnvState &state) {
    LOG_GDB("Starting GDB Server...");

#ifdef _WIN32
    int32_t err = WSAStartup(MAKEWORD(2, 2), &state.gdb.wsaData);
    if (err) {
        LOG_GDB("GDB Server Failed: Could not start WSA service.");
        return;
    }
#endif

    state.gdb.listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (state.gdb.listen_socket == -1) {
        LOG_GDB("GDB Server Failed: Could not create socket.");
        return;
    }

    sockaddr_in socket_address{};
    socket_address.sin_family = AF_INET;
    socket_address.sin_port = htons(GDB_SERVER_PORT);
#ifdef _WIN32
    socket_address.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
#else
    socket_address.sin_addr.s_addr = htonl(INADDR_ANY);
#endif

    if (bind(state.gdb.listen_socket, (sockaddr *)&socket_address, sizeof(socket_address)) == -1) {
        LOG_GDB("GDB Server Failed: Could not bind socket.");
        return;
    }

    if (listen(state.gdb.listen_socket, 1) == -1) {
        LOG_GDB("GDB Server Failed: Could not listen on socket.");
        return;
    }

    state.gdb.server_thread = std::make_shared<std::thread>(server_listen, std::ref(state));

    LOG_INFO("GDB Server is listening on port {}", GDB_SERVER_PORT);
}

void server_close(EmuEnvState &state) {
#ifdef _WIN32
    if (state.gdb.client_socket != BAD_SOCK)
        closesocket(state.gdb.client_socket);
    closesocket(state.gdb.listen_socket);
    WSACleanup();
#else
    if(state.gdb.client_socket != BAD_SOCK)
        close(state.gdb.client_socket);
    close(state.gdb.listen_socket);
#endif

    state.gdb.client_socket = BAD_SOCK;
    state.gdb.listen_socket = BAD_SOCK;

    state.gdb.server_die = true;
    if (state.gdb.server_thread && state.gdb.server_thread->get_id() != std::this_thread::get_id())
        state.gdb.server_thread->join();
}
