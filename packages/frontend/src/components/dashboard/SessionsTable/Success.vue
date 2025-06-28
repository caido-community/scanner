<script setup lang="ts">
import { formatDistanceToNow } from "date-fns";
import Badge from "primevue/badge";
import Button from "primevue/button";
import Card from "primevue/card";
import Column from "primevue/column";
import DataTable from "primevue/datatable";
import Dropdown from "primevue/dropdown";
import IconField from "primevue/iconfield";
import InputIcon from "primevue/inputicon";
import InputText from "primevue/inputtext";
import { ref } from "vue";

import { useTable } from "./useTable";

import { type SessionsState } from "@/types/scanner";

defineProps<{
  state: SessionsState & { type: "Success" };
}>();

const search = ref("");
const statusFilter = ref("all");

const statusOptions = [
  { label: "All Sessions", value: "all" },
  { label: "Running", value: "running" },
  { label: "Finished", value: "finished" },
];

const {
  filters,
  getFilteredSessions,
  getStatusSeverity,
  getStatusIcon,
  getRequestsCount,
  getSeverityBadgeData,
} = useTable({ search, statusFilter });
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
          <h3 class="text-lg font-semibold">Sessions</h3>
          <p class="text-sm text-surface-300 flex-1">
            Active and completed vulnerability scanning sessions.
          </p>
        </div>

        <div class="flex gap-2 items-center">
          <Dropdown
            v-model="statusFilter"
            :options="statusOptions"
            option-label="label"
            option-value="value"
            placeholder="Filter by status"
            class="w-40"
          />

          <IconField>
            <InputIcon class="fas fa-magnifying-glass" />
            <InputText
              v-model="search"
              placeholder="Search sessions"
              class="w-full"
            />
          </IconField>
        </div>
      </div>

      <DataTable
        :value="getFilteredSessions(state.sessions)"
        scrollable
        scroll-height="flex"
        striped-rows
        :filters="filters"
        :global-filter-fields="['kind', 'id']"
        size="small"
        class="flex-1"
      >
        <template #empty>
          <div class="flex justify-center items-center h-32">
            <span class="text-surface-400">No sessions found</span>
          </div>
        </template>

        <Column field="kind" header="Status" class="w-32">
          <template #body="{ data }">
            <Badge
              :value="data.kind"
              :icon="getStatusIcon(data.kind)"
              :severity="getStatusSeverity(data.kind)"
            />
          </template>
        </Column>

        <Column header="Requests" class="w-24">
          <template #body="{ data }">
            {{ getRequestsCount(data) }}
          </template>
        </Column>

        <Column header="Findings" class="min-w-48">
          <template #body="{ data }">
            <div class="flex flex-wrap gap-1">
              <template v-if="getSeverityBadgeData(data).length > 0">
                <Badge
                  v-for="badge in getSeverityBadgeData(data)"
                  :key="badge.severity"
                  :value="`${badge.count} ${badge.severity}`"
                  :severity="badge.color"
                  size="small"
                />
              </template>
              <span v-else class="text-surface-400">0</span>
            </div>
          </template>
        </Column>

        <Column field="createdAt" header="Created" class="w-40">
          <template #body="{ data }">
            <div class="text-sm">
              {{
                formatDistanceToNow(new Date(data.createdAt), {
                  addSuffix: true,
                })
              }}
            </div>
          </template>
        </Column>

        <Column class="w-32" body-style="text-align:center">
          <template #body="{ data }">
            <div class="flex gap-1">
              <Button
                text
                severity="contrast"
                icon="fas fa-eye"
                size="small"
                title="View Details"
              />
              <Button
                v-if="data.kind === 'Running'"
                text
                severity="secondary"
                icon="fas fa-stop"
                size="small"
                title="Stop Session"
              />
              <Button
                text
                severity="danger"
                icon="fas fa-trash"
                size="small"
                title="Delete Session"
                :disabled="data.kind === 'Running'"
              />
            </div>
          </template>
        </Column>
      </DataTable>
    </template>
  </Card>
</template>
