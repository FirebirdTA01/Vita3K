// Vita3K emulator project
// Copyright (C) 2022 Vita3K team
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

#pragma once

#include <array>
#include <cstdint>
#include <mutex>
#include <vector>

#include <mem/ptr.h>
#include <util/types.h>

#include <mem/mempool.h>
#include <ngs/common.h>
#include <ngs/scheduler.h>

struct MemState;
struct KernelState;

namespace ngs {
// random number of bytes to make sure nothing bad happens
constexpr size_t default_passthrough_parameter_size = 140;
constexpr size_t default_normal_parameter_size = 100;

enum VoiceState {
    VOICE_STATE_AVAILABLE,
    VOICE_STATE_ACTIVE,
    VOICE_STATE_FINALIZING,
    VOICE_STATE_UNLOADING,
};

struct VoicePreset {
    SceInt32 name_offset;
    SceUInt32 name_length;
    SceInt32 preset_data_offset;
    SceUInt32 preset_data_size;
    SceInt32 bypass_flags_offset;
    SceUInt32 bypass_flags_nb;
};

struct ParametersDescriptor {
    SceUInt32 id;
    SceUInt32 size;
};

struct ModuleParameterHeader {
    SceInt32 module_id;
    SceInt32 channel;
};

struct BufferParamsInfo {
    Ptr<void> data;
    SceUInt32 size;
};

struct State;
struct Voice;

struct CallbackInfo {
    Ptr<void> voice_handle;
    Ptr<void> rack_handle;
    std::uint32_t module_id;
    std::uint32_t callback_reason;
    std::uint32_t callback_reason_2;
    Ptr<void> callback_ptr;
    Ptr<void> userdata;
};

struct ModuleData {
    Voice *parent;
    std::uint32_t index;

    Ptr<void> callback;
    Ptr<void> user_data;

    bool is_bypassed;

    std::vector<std::uint8_t> voice_state_data; ///< Voice state.
    std::vector<std::uint8_t> extra_storage; ///< Local data storage for module.

    BufferParamsInfo info;
    std::vector<std::uint8_t> last_info;

    enum Flags {
        PARAMS_LOCK = 1 << 0,
    };

    std::uint8_t flags;

    explicit ModuleData();

    template <typename T>
    T *get_state() {
        if (voice_state_data.size() == 0) {
            voice_state_data.resize(sizeof(T));
            new (&voice_state_data[0]) T();
        }

        return reinterpret_cast<T *>(&voice_state_data[0]);
    }

    template <typename T>
    T *get_parameters(const MemState &mem) {
        if (flags & PARAMS_LOCK) {
            // Use our previous set of data
            return reinterpret_cast<T *>(&last_info[0]);
        }

        return info.data.cast<T>().get(mem);
    }

    void fill_to_fit_granularity();

    void invoke_callback(KernelState &kern, const MemState &mem, const SceUID thread_id, const std::uint32_t reason1,
        const std::uint32_t reason2, Address reason_ptr);

    BufferParamsInfo *lock_params(const MemState &mem);
    bool unlock_params(const MemState &mem);
};

struct Module {
    BussType buss_type;

    explicit Module(BussType buss_type)
        : buss_type(buss_type) {}
    virtual ~Module() = default;

    virtual bool process(KernelState &kern, const MemState &mem, const SceUID thread_id, ModuleData &data, std::unique_lock<std::recursive_mutex> &scheduler_lock, std::unique_lock<std::mutex> &voice_lock) = 0;
    virtual std::uint32_t module_id() const { return 0; }
    virtual std::size_t get_buffer_parameter_size() const = 0;
    virtual void on_state_change(ModuleData &v, const VoiceState previous) {}
    virtual void on_param_change(const MemState &mem, ModuleData &data) {}
};

static constexpr std::uint32_t MAX_VOICE_OUTPUT = 8;

struct VoiceDefinition {
    virtual void new_modules(std::vector<std::unique_ptr<Module>> &mods) = 0;
    virtual std::size_t get_total_buffer_parameter_size() const = 0;
    virtual std::uint32_t output_count() const = 0;
};

struct SystemInitParameters {
    std::int32_t max_racks;
    std::int32_t max_voices;
    std::int32_t granularity;
    std::int32_t sample_rate;
    std::int32_t unk16;
};

struct Voice;

struct PatchSetupInfo {
    Ptr<Voice> source;
    std::int32_t source_output_index;
    std::int32_t source_output_subindex;
    Ptr<Voice> dest;
    std::int32_t dest_input_index;
};

struct Patch {
    std::int32_t output_index;
    std::int32_t output_sub_index;
    std::int32_t dest_index;
    Voice *dest;
    Voice *source;

    float volume_matrix[2][2];
};

struct RackDescription {
    Ptr<VoiceDefinition> definition;
    std::int32_t voice_count;
    std::int32_t channels_per_voice;
    std::int32_t max_patches_per_input;
    std::int32_t patches_per_output;
    Ptr<void> unk14;
};

struct Rack;

struct VoiceProduct {
    std::uint8_t reserved[2];
    std::uint8_t *data;
};

struct VoiceInputManager {
    using PCMInput = std::vector<std::uint8_t>;
    using PCMInputs = std::vector<PCMInput>;

    PCMInputs inputs;

    void init(const std::uint32_t granularity, const std::uint16_t total_input);
    void reset_inputs();

    PCMInput *get_input_buffer_queue(const std::int32_t index);
    std::int32_t receive(Patch *patch, const VoiceProduct &data);
};

struct Voice {
    Rack *rack;

    std::vector<ModuleData> datas;
    VoiceState state;
    bool is_pending;
    bool is_paused;
    bool is_keyed_off;
    std::uint32_t frame_count;

    using Patches = std::vector<Ptr<Patch>>;

    std::array<Patches, MAX_OUTPUT_PORT> patches;

    VoiceInputManager inputs;

    std::unique_ptr<std::mutex> voice_mutex;
    VoiceProduct products[MAX_VOICE_OUTPUT];

    Ptr<void> finished_callback;
    Ptr<void> finished_callback_user_data;

    void init(Rack *mama);

    ModuleData *module_storage(const std::uint32_t index);

    bool remove_patch(const MemState &mem, const Ptr<Patch> patch);
    Ptr<Patch> patch(const MemState &mem, const std::int32_t index, std::int32_t subindex, std::int32_t dest_index, Voice *dest);

    void transition(const VoiceState new_state);
    bool parse_params(const MemState &mem, const ModuleParameterHeader *header);
    // Return the number of errors that happened
    SceInt32 parse_params_block(const MemState &mem, const ModuleParameterHeader *header, const SceUInt32 size);
    bool set_preset(const MemState &mem, const VoicePreset *preset);

    void invoke_callback(KernelState &kernel, const MemState &mem, const SceUID thread_id, Ptr<void> callback, Ptr<void> user_data,
        const std::uint32_t module_id, const std::uint32_t reason = 0, const std::uint32_t reason2 = 0, Address reason_ptr = 0);
};

struct System;

struct Rack : public MempoolObject {
    System *system;
    VoiceDefinition *vdef;

    std::int32_t channels_per_voice;
    std::int32_t max_patches_per_input;
    std::int32_t patches_per_output;

    std::vector<Ptr<Voice>> voices;
    std::vector<std::unique_ptr<Module>> modules;

    explicit Rack(System *mama, const Ptr<void> memspace, const std::uint32_t memspace_size);

    static std::uint32_t get_required_memspace_size(MemState &mem, RackDescription *description);
};

struct System : public MempoolObject {
    std::vector<Rack *> racks;
    std::int32_t max_voices;
    std::int32_t granularity;
    std::int32_t sample_rate;

    VoiceScheduler voice_scheduler;

    explicit System(const Ptr<void> memspace, const std::uint32_t memspace_size);
    static std::uint32_t get_required_memspace_size(SystemInitParameters *parameters);
};

bool deliver_data(const MemState &mem, Voice *source, const std::uint8_t output_port,
    const VoiceProduct &data_to_deliver);

bool init_system(State &ngs, const MemState &mem, SystemInitParameters *parameters, Ptr<void> memspace, const std::uint32_t memspace_size);
void release_system(State &ngs, const MemState &mem, System *system);
bool init_rack(State &ngs, const MemState &mem, System *system, BufferParamsInfo *init_info, const RackDescription *description);
void release_rack(State &ngs, const MemState &mem, System *system, Rack *rack);

Ptr<VoiceDefinition> get_voice_definition(State &ngs, MemState &mem, ngs::BussType type);
} // namespace ngs
