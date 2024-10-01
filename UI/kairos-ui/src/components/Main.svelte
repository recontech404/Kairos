<script>
    import { onMount } from 'svelte';
    import { env } from "$env/dynamic/public"
    import AddJob from "./AddJob.svelte";
    import DisplayJobs from "./DisplayJobs.svelte";
    import Settings from "./Settings.svelte";
    let isAddJobOpen = false;
    let showSettings = false;
    let settings = null;
    let runnersOnlineCnt = 0;

    function openAddJob(){
        isAddJobOpen = true;
    }

    function closeAddJob(){
        isAddJobOpen = false;
    }

    onMount(async () => {
      try {
        const response = await fetch(env.PUBLIC_BASE_URL+'/ui/dashboard');
        if (!response.ok){
          throw new Error('Network response was not ok')
        }
        runnersOnlineCnt = await response.json();
      } catch (err) {
        error = err.message;
      }
    })

    async function fetchSettings(){
        const response = await fetch(env.PUBLIC_BASE_URL+'/ui/settings');
        if (response.ok){
            settings = await response.json();
            showSettings = true;
        } else {
            console.error("unable to fetch settings")
        }
    }

    function closeSettings(){
        showSettings = false;
    }
</script>


<button on:click={openAddJob} class="absolute top-20 right-20 bg-blue-800 text-white font-bold py-2 px-4 rounded-full hover:bg-blue-700">Add Job</button>

<button on:click={fetchSettings} class="absolute top-10 left-10 bg-slate-800 text-white font-bold py-2 px-4 rounded-full hover:bg-blue-700">Settings</button>

<div class="absolute top-12 left-36 inline-flex items-center">
    <p class="font-semibold text-white">Runner Online:</p>
    {#if runnersOnlineCnt.runners_online_cnt > 0}
      <div class="w-4 h-4 bg-green-500 rounded-full ml-2 mt-1"></div>
    {:else}
        <div class="w-4 h-4 bg-red-500 rounded-full ml-2 mt-1"></div>
    {/if}
</div>
  

<AddJob isAddJobOpen={isAddJobOpen} closeAddJob={closeAddJob}/>
<Settings showSettings={showSettings} settings={settings} closeSettings={closeSettings}/>
<DisplayJobs/>