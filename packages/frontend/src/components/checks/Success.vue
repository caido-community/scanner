<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import Checkbox from "primevue/checkbox";
import Column from "primevue/column";
import ContextMenu from "primevue/contextmenu";
import DataTable from "primevue/datatable";
import Dialog from "primevue/dialog";
import IconField from "primevue/iconfield";
import InputIcon from "primevue/inputicon";
import InputText from "primevue/inputtext";

import CheckExpansion from "./Expansion.vue";
import { useCheckPresets } from "./usePresets";
import { useTable } from "./useTable";

const {
  search,
  expandedRows,
  filters,
  checks,
  getPassiveEnabled,
  getActiveEnabled,
  togglePassiveCheck,
  toggleActiveCheck,
  getAggressivityText,
  getAggressivityBadgeClass,
} = useTable();

const {
  showNewPresetDialog,
  newPresetName,
  menu,
  menuModel,
  presets,
  handleNewPreset,
  handleSaveNewPreset,
  handleCancelNewPreset,
  onPresetContextMenu,
  applyPreset,
} = useCheckPresets();
</script>

<template>
  <ContextMenu :ref="menu" :model="menuModel" />
  <Card
    class="h-full"
    :pt="{
      body: { class: 'h-full p-0' },
      content: { class: 'h-full flex flex-col' },
    }"
  >
    <template #content>
      <div class="flex justify-between items-center p-4 gap-4">
        <div class="flex-1">
          <h3 class="text-lg font-semibold">Checks</h3>
          <p class="text-sm text-surface-300 flex-1">
            Configure which vulnerability checks are enabled for passive and
            active scanning.
          </p>
        </div>

        <IconField>
          <InputIcon class="fas fa-magnifying-glass" />
          <InputText
            v-model="search"
            placeholder="Search checks"
            class="w-full"
          />
        </IconField>
      </div>

      <DataTable
        v-model:expanded-rows="expandedRows"
        :value="checks"
        scrollable
        scroll-height="flex"
        striped-rows
        :filters="filters"
        :global-filter-fields="['name', 'id', 'description']"
        size="small"
        class="flex-1 overflow-auto"
        expandable-rows
        removable-sort
      >
        <template #empty>
          <div class="flex justify-center items-center h-32">
            <span class="text-surface-400">No checks found</span>
          </div>
        </template>

        <Column :expander="true" header-style="width: 3rem" />

        <Column field="name" header="Name" class="min-w-48">
          <template #body="{ data }">
            <div>
              <div class="font-medium">{{ data.name }}</div>
              <div class="text-xs text-surface-400">{{ data.id }}</div>
            </div>
          </template>
        </Column>

        <Column field="description" header="Description" class="min-w-64">
          <template #body="{ data }">
            <div class="text-sm">{{ data.description }}</div>
          </template>
        </Column>

        <Column
          field="aggressivity"
          header="Aggressivity"
          class="min-w-48"
          sortable
          sort-field="aggressivity.maxRequests"
        >
          <template #body="{ data }">
            <div
              class="inline-flex px-2 rounded-md text-sm font-mono"
              :class="getAggressivityBadgeClass(data.aggressivity)"
            >
              {{ getAggressivityText(data) }}
            </div>
          </template>
        </Column>

        <Column header="Passive" class="w-20">
          <template #body="{ data }">
            <div class="flex justify-center">
              <Checkbox
                :model-value="getPassiveEnabled(data)"
                binary
                @update:model-value="togglePassiveCheck(data)"
              />
            </div>
          </template>
        </Column>

        <Column header="Active" class="w-20">
          <template #body="{ data }">
            <div class="flex justify-center">
              <Checkbox
                :model-value="getActiveEnabled(data)"
                binary
                @update:model-value="toggleActiveCheck(data)"
              />
            </div>
          </template>
        </Column>

        <template #expansion="{ data }">
          <CheckExpansion :check="data" />
        </template>

        <template #footer>
          <div class="flex justify-between items-center">
            <div class="flex items-center gap-4">
              <div class="text-sm text-surface-300">Presets</div>
              <div class="flex flex-wrap gap-2">
                <Button
                  v-for="preset in presets"
                  :key="preset.name"
                  :label="preset.name"
                  size="small"
                  severity="info"
                  outlined
                  @click="applyPreset(preset)"
                  @contextmenu="onPresetContextMenu($event, preset)"
                />
                <Button
                  label="New Preset"
                  size="small"
                  severity="secondary"
                  outlined
                  icon="fas fa-plus"
                  class="text-xs"
                  @click="handleNewPreset"
                />
              </div>
            </div>
          </div>
        </template>
      </DataTable>
    </template>
  </Card>

  <Dialog
    v-model:visible="showNewPresetDialog"
    modal
    header="Create New Preset"
    :style="{ width: '25rem' }"
  >
    <div class="flex flex-col gap-4">
      <div>
        <label for="presetName" class="block text-sm font-medium mb-2">
          Preset Name
        </label>
        <InputText
          id="presetName"
          v-model="newPresetName"
          placeholder="Enter preset name"
          class="w-full"
          @keyup.enter="handleSaveNewPreset"
        />
      </div>
      <div class="text-sm text-surface-400">
        This will save the current configuration of enabled/disabled checks as a
        new preset.
      </div>
    </div>
    <template #footer>
      <div class="flex justify-end gap-2">
        <Button
          label="Cancel"
          severity="secondary"
          outlined
          @click="handleCancelNewPreset"
        />
        <Button
          label="Save"
          :disabled="!newPresetName.trim()"
          @click="handleSaveNewPreset"
        />
      </div>
    </template>
  </Dialog>
</template>
