<script setup lang="ts">
import { type EditorView } from "@codemirror/view";
import { onBeforeUnmount, onMounted, ref, watch } from "vue";

import { useSDK } from "@/plugins/sdk";

const { raw } = defineProps<{
  raw: string;
}>();

const sdk = useSDK();
const root = ref<HTMLElement>();
const editorView = ref<EditorView>();

const updateEditorContent = (content: string) => {
  if (editorView.value === undefined) {
    return;
  }

  editorView.value.dispatch({
    changes: {
      from: 0,
      to: editorView.value.state.doc.length,
      insert: content,
    },
  });
};

const initializeEditor = () => {
  if (root.value === undefined || editorView.value !== undefined) {
    return;
  }

  const editor = sdk.ui.httpResponseEditor();
  root.value.appendChild(editor.getElement());
  editorView.value = editor.getEditorView();
  updateEditorContent(raw);
};

onMounted(() => {
  initializeEditor();
});

watch(
  () => raw,
  (newRaw) => {
    updateEditorContent(newRaw);
  },
);

onBeforeUnmount(() => {
  editorView.value = undefined;
  Array.from(root.value?.children ?? []).forEach((child) => {
    child.remove();
  });
});
</script>

<template>
  <div
    ref="root"
    class="flex h-full min-h-0 flex-col overflow-hidden [&>*]:flex-1 [&>*]:min-h-0 [&>*]:overflow-hidden"
  ></div>
</template>
