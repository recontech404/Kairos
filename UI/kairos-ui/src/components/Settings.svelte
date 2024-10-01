<script>
    import {onMount} from 'svelte'
    import { env } from "$env/dynamic/public"

    export let settings;
    export let showSettings;
    export let closeSettings;

    let errorMessage = "";

    async function saveSettings() {
        const response = await fetch (env.PUBLIC_BASE_URL+'/ui/settings',{
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(settings),
        });

        if (response.ok){
            console.log("Settings saved");
            errorMessage = "";
            closeSettings();
        } else {
            const errorResponse = await response.json();
            console.error('Error:', errorResponse.error);
            errorMessage = "Error: " + errorResponse.error;
            setTimeout(() =>{
            errorMessage = "";
            }, 5000)
        }
    }
</script>

<style>
    .error-message {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      background-color: red;
      color: white;
      padding: 10px;
      text-align: center;
      z-index: 1000;
    }
</style>

{#if showSettings}
<div class="fixed inset-0 flex items-center justify-center bg-black-700 bg-opacity-80 z-30 pointer-events-auto">
  <div class="bg-slate-800 rounded-lg p-6 w-1/3 max-h-screen overflow-y-auto">
      <h2 class="text-xl font-bold mb-4">Settings</h2>
      <form on:submit|preventDefault={saveSettings}>
          <div class="mb-4">
              <label for="name" class="block text-sm font-medium">Name</label>
              <input type="text" bind:value={settings.name} class="mt-1 block w-1/2 border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" />
          </div>
          <div class="mb-4">
              <label for="model" class="block text-sm font-medium">Model:</label>
              <input type="text" bind:value={settings.model} class="mt-1 block w-1/2 border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" />
          </div>
          <div class="mb-4">
              <label for="top_k" class="block text-sm font-medium">Top K:</label>
              <input type="number" bind:value={settings.top_k} class="mt-1 block w-1/4 border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" />
          </div>
          <div class="mb-4">
              <label for="top_P" class="block text-sm font-medium">Top P:</label>
              <input type="number" step="0.01" bind:value={settings.top_p} class="mt-1 block w-1/4 border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" />
          </div>
          <div class="mb-4">
              <label for="temp" class="block text-sm font-medium">Temperature:</label>
              <input type="number" step="0.01" bind:value={settings.temperature} class="mt-1 block w-1/4 border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" />
          </div>
          <div class="mb-4">
              <label for="repeat_pen" class="block text-sm font-medium">Repeat Pen:</label>
              <input type="number" step="0.01" bind:value={settings.repeat_pen} class="mt-1 block w-1/4 border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" />
          </div>
          <div class="mb-4">
              <label for="ctx_length" class="block text-sm font-medium">Context Length:</label>
              <input type="number" bind:value={settings.ctx_length} class="mt-1 block w-1/4 border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" />
          </div>
          <div class="mb-4">
              <label for="system_prompt" class="block text-sm font-medium">System Prompt:</label>
              <textarea bind:value={settings.system_prompt} class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" rows="4"></textarea>
          </div>
          <div class="flex justify-between">
              <button type="submit" class="bg-blue-600 text-white font-bold py-2 px-4 rounded hover:bg-blue-500">Save Settings</button>
              <button type="button" on:click={closeSettings} class="bg-gray-300 text-gray-700 font-bold py-2 px-4 rounded hover:bg-gray-200">Close</button>
          </div>
      </form>
  </div>
</div>
{/if}

{#if errorMessage}
  <div class="error-message">
    {errorMessage}
  </div>
{/if}