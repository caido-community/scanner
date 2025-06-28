<script setup lang="ts">
import Card from "primevue/card";
import Checkbox from "primevue/checkbox";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Dropdown from "primevue/dropdown";
import IconField from "primevue/iconfield";
import InputIcon from "primevue/inputicon";
import InputText from "primevue/inputtext";
import { ref } from "vue";

import CheckExpansion from "./Expansion.vue";
import { useTable } from "./useTable";

import { type ChecksState } from "@/types/checks";

defineProps<{
  state: ChecksState & { type: "Success" };
}>();

const search = ref("");
const typeFilter = ref("all");
const expandedRows = ref([]);

const typeOptions = [
  { label: "All Checks", value: "all" },
  { label: "Passive", value: "passive" },
  { label: "Active", value: "active" },
];

const {
  filters,
  getFilteredChecks,
  getPassiveEnabled,
  getActiveEnabled,
  togglePassiveCheck,
  toggleActiveCheck
} = useTable({ search, typeFilter });
</script>
<template>
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
          <h3 class="text-lg font-semibold">Vulnerability Checks</h3>
          <p class="text-sm text-surface-300 flex-1">
            Configure which vulnerability checks are enabled for passive and
            active scanning.
          </p>
        </div>

        <div class="flex gap-2 items-center">
          <Dropdown
            v-model="typeFilter"
            :options="typeOptions"
            option-label="label"
            option-value="value"
            placeholder="Filter by type"
            class="w-40"
          />

          <IconField>
            <InputIcon class="fas fa-magnifying-glass" />
            <InputText
              v-model="search"
              placeholder="Search checks"
              class="w-full"
            />
          </IconField>
        </div>
      </div>

      <DataTable
        v-model:expanded-rows="expandedRows"
        :value="getFilteredChecks(state.checks)"
        scrollable
        scroll-height="flex"
        striped-rows
        :filters="filters"
        :global-filter-fields="['name', 'id', 'description']"
        size="small"
        class="flex-1"
        expandable-rows
        data-key="id"
      >
        <template #empty>
          <div class="flex justify-center items-center h-32">
            <span class="text-surface-400">No checks found</span>
          </div>
        </template>

        <Column :expander="true" header-style="width: 3rem" />

        <Column field="name" header="Check Name" class="min-w-48">
          <template #body="{ data }">
            <div>
              <div class="font-medium">{{ data.name }}</div>
              <div class="text-xs text-surface-400">{{ data.id }}</div>
            </div>
          </template>
        </Column>

        <Column field="type" header="Type" class="w-24">
          <template #body="{ data }">
            <span class="capitalize text-sm">{{ data.type }}</span>
          </template>
        </Column>

        <Column field="description" header="Description" class="min-w-64">
          <template #body="{ data }">
            <div class="text-sm">{{ data.description }}</div>
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
      </DataTable>
    </template>
  </Card>
</template>
