<script setup lang="ts">
import Button from "primevue/button";
import Card from "primevue/card";
import Checkbox from "primevue/checkbox";
import ContextMenu from "primevue/contextmenu";
import Dialog from "primevue/dialog";
import IconField from "primevue/iconfield";
import InputIcon from "primevue/inputicon";
import InputText from "primevue/inputtext";
import { DynamicScroller, DynamicScrollerItem } from "vue-virtual-scroller";

import CheckExpansion from "./Expansion.vue";
import { useCheckPresets } from "./usePresets";
import { useTable } from "./useTable";

const {
  search,
  visibleChecks,
  isExpandedCheck,
  toggleExpandedCheck,
  toggleAggressivitySort,
  getAggressivitySortIcon,
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

const columnWidths = {
  expander: "3rem",
  name: "26%",
  description: "40%",
  aggressivity: "22%",
  passive: "5%",
  active: "5%",
} as const;
</script>

<template>
  <ContextMenu :ref="menu" :model="menuModel" />
  <Card
    class="h-full"
    :pt="{
      body: { class: 'h-full p-0' },
      content: { class: 'h-full flex flex-col min-h-0' },
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

      <div class="flex-1 min-h-0 flex flex-col">
        <div class="overflow-y-scroll" style="scrollbar-gutter: stable">
          <table class="w-full border-spacing-0 border-separate table-fixed">
            <thead class="bg-surface-900">
              <tr class="text-surface-0/70">
                <th
                  class="font-normal leading-[normal] border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.expander }"
                />
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.name }"
                >
                  Name
                </th>
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.description }"
                >
                  Description
                </th>
                <th
                  class="font-normal leading-[normal] text-left border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2 cursor-pointer hover:bg-surface-700/50"
                  :style="{ width: columnWidths.aggressivity }"
                  @click="toggleAggressivitySort"
                >
                  <span class="flex items-center gap-2">
                    Aggressivity
                    <i :class="getAggressivitySortIcon()" class="text-xs" />
                  </span>
                </th>
                <th
                  class="font-normal leading-[normal] text-center border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.passive }"
                >
                  Passive
                </th>
                <th
                  class="font-normal leading-[normal] text-center border-y-2 border-x-0 border-solid border-surface-900 py-[0.375rem] px-2"
                  :style="{ width: columnWidths.active }"
                >
                  Active
                </th>
              </tr>
            </thead>
          </table>
        </div>

        <div
          v-if="visibleChecks.length === 0"
          class="flex-1 min-h-0 flex justify-center items-center"
        >
          <span class="text-surface-400">No checks found</span>
        </div>

        <DynamicScroller
          v-else
          class="flex-1 overflow-auto"
          style="scrollbar-gutter: stable"
          :items="visibleChecks"
          :min-item-size="40"
          key-field="id"
        >
          <template #default="{ item, index, active }">
            <DynamicScrollerItem
              :item="item"
              :active="active"
              :size-dependencies="[isExpandedCheck(item.id)]"
            >
              <table
                class="w-full border-spacing-0 border-separate table-fixed"
              >
                <tbody>
                  <tr
                    :class="[
                      index % 2 === 0 ? 'bg-surface-800' : 'bg-surface-900',
                      'text-sm',
                    ]"
                  >
                    <td
                      class="leading-[normal] border-0 py-[0.375rem] px-2 align-middle"
                      :style="{ width: columnWidths.expander }"
                    >
                      <Button
                        text
                        rounded
                        severity="secondary"
                        :icon="
                          isExpandedCheck(item.id)
                            ? 'fas fa-chevron-down'
                            : 'fas fa-chevron-right'
                        "
                        :pt="{ root: { class: '!w-6 !h-6 !p-0' } }"
                        @click.stop="toggleExpandedCheck(item.id)"
                      />
                    </td>
                    <td
                      class="leading-[normal] text-left border-0 py-[0.375rem] px-2 align-top"
                      :style="{ width: columnWidths.name }"
                    >
                      <div>
                        <div class="font-medium truncate text-[0.9rem]">{{ item.name }}</div>
                        <div class="text-xs text-surface-400 truncate">
                          {{ item.id }}
                        </div>
                      </div>
                    </td>
                    <td
                      class="leading-[normal] text-left border-0 py-[0.375rem] px-2 align-middle"
                      :style="{ width: columnWidths.description }"
                    >
                      <div class="text-sm truncate">{{ item.description }}</div>
                    </td>
                    <td
                      class="leading-[normal] text-left border-0 py-[0.375rem] px-2 align-middle"
                      :style="{ width: columnWidths.aggressivity }"
                    >
                      <div
                        class="inline-flex rounded-md text-sm font-mono"
                        :class="getAggressivityBadgeClass(item.aggressivity)"
                      >
                        {{ getAggressivityText(item) }}
                      </div>
                    </td>
                    <td
                      class="leading-[normal] text-center border-0 py-[0.375rem] px-2 align-middle"
                      :style="{ width: columnWidths.passive }"
                    >
                      <Checkbox
                        :model-value="getPassiveEnabled(item)"
                        binary
                        @update:model-value="togglePassiveCheck(item)"
                      />
                    </td>
                    <td
                      class="leading-[normal] text-center border-0 py-[0.375rem] px-2 align-middle"
                      :style="{ width: columnWidths.active }"
                    >
                      <Checkbox
                        :model-value="getActiveEnabled(item)"
                        binary
                        @update:model-value="toggleActiveCheck(item)"
                      />
                    </td>
                  </tr>
                  <tr
                    v-if="isExpandedCheck(item.id)"
                    :class="
                      index % 2 === 0 ? 'bg-surface-800' : 'bg-surface-900'
                    "
                  >
                    <td :colspan="6" class="border-t border-surface-700">
                      <CheckExpansion :check="item" />
                    </td>
                  </tr>
                </tbody>
              </table>
            </DynamicScrollerItem>
          </template>
        </DynamicScroller>

        <div class="border-t border-surface-700 p-3">
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
        </div>
      </div>
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
