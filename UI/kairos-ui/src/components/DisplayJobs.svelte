<script>
    import { env } from "$env/dynamic/public"
    import { onMount } from 'svelte';

    let jobs = [];
    let loading = true;
    let error = null;

    let selectedJob = null;
    let showJobModal = false;

    let showCMDModal = false;
    let cmdData = null;

    let showMetadataModal = false;
    let metadataC2 = null;
    let metadataSSL = null;
    let showMetadataSSLModal = false;
    let showMetadataC2Modal = false;

    function openJobModal(job) {
        selectedJob = job;
        showJobModal = true;
    }

    function closeJobModal() {
        showJobModal = false;
        selectedJob = null;
    }

    function closeCMDModel(){
      showCMDModal = false;
      cmdData = null;
    }

    function closeMetadataModal(){
      showMetadataModal = false;
      metadataC2 = null;
      metadataSSL = null;
    }

    function openMetadataSSLModal(){
      showMetadataSSLModal = true;
    }

    function closeMetadataSSLModal(){
      showMetadataSSLModal = false;
    }

    function openMetadataC2Modal() {
      showMetadataC2Modal = true;
    }

    function closeMetadataC2Modal(){
      showMetadataC2Modal = false;
    }

    async function reRequestLLM(){
      const confirmed = confirm(`Are you sure you want to request LLM?`);
      if (confirmed){
        const payload = {
          jobID: selectedJob.jobID
        };
        
        const response = await fetch(env.PUBLIC_BASE_URL+'/ui/rellm', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)  
        });
        
        if (response.ok){
          console.log("Rellm Success")
        } else {
          console.Error("Error: ", data.message)
        }
      }
    }

    async function requestMetadata(){
      const payload = {
        jobID: selectedJob.jobID
      };

      const response = await fetch(env.PUBLIC_BASE_URL+"/ui/metadata",{
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      })

      if (response.ok){
        const data = await response.json();
        metadataC2 = data.c2_ipp_map;
        metadataSSL = data.ssl_map;
        showMetadataModal = true;
      } else {
        console.error("cmddata err")
      }
    }

    async function requestC2Data(){
      const payload = {
        jobID: selectedJob.jobID
      };

      const response = await fetch(env.PUBLIC_BASE_URL+"/ui/cmddata",{
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      })

      if (response.ok){
        const data = await response.json();
        cmdData = data.cmd_data;
        showCMDModal = true;
      } else {
        console.error("cmddata err")
      }
    }

    async function deleteJob(){
      const confirmed = confirm(`Are you sure you want to delete job?`);
      if (confirmed){
        const payload = {
          jobID: selectedJob.jobID
        };

        const response = await fetch(env.PUBLIC_BASE_URL+'/ui/deljob', {
          method: 'DELETE',
          headers: {
            'Content-Type': 'application/json'
          },
          body: JSON.stringify(payload)
        });

        if (response.ok){
          location.reload();
        } else {

        }
      }
      
    }

    const getRowColor = (status) => {
    switch (status) {
      case 'success':
        return 'bg-blue-950';
      case 'failed':
        return 'bg-red-700';
      case 'llm_timeout':
        return 'bg-red-900'
      case 'timeout':
        return 'bg-red-900'
      case 'running':
        return 'bg-blue-800'
      case 'pending':
        return 'bg-blue-800'
      case 'no_events':
        return 'bg-yellow-500'
      default:
        return 'bg-gray-100';
    }
  };
  
    onMount(async () => {
      try {
        const response = await fetch(env.PUBLIC_BASE_URL+'/ui/jobs');
        if (!response.ok) {
          throw new Error('Network response was not ok');
        }
        jobs = await response.json();
      } catch (err) {
        error = err.message;
      } finally {
        loading = false;
      }
    });

</script>

<div class="flex justify-center items-center h-full">
  <div class="overflow-auto max-h-[80vh] w-[60vw] mt-20">
    <table class="min-w-full border-collapse border border-gray-800">
      <thead>
        <tr class="bg-gray-800">
          <th class="border border-gray-800 p-2">Name</th>
          <th class="border border-gray-800 p-2">SHA256</th>
          <th class="border border-gray-800 p-2">Status</th>
          <th class="border border-gray-800 p-2">Submitted At</th>
          <th class="border border-gray-800 p-2">Details</th>
        </tr>
      </thead>
      {#if jobs && jobs.length >0}
      <tbody>
      
        {#each jobs as job}
        <tr class={`border-b border-gray-800 hover:bg-gray-600 ${getRowColor(job.job_status)}`}>
            <td class="border border-gray-800 p-2 text-center">{job.name}</td>
            <td class="border-hidden border-gray-800 p-2 flex justify-center relative">
              <span class="truncate">{job.sha256 ? job.sha256.slice(0, 15) : 'Not Available'}</span>
              <span class="absolute left-0 top-0 w-full h-full bg-grey opacity-0 hover:opacity-100 transition-opacity duration-300">
                {job.sha256}
              </span>
            </td>
            <td class="border border-gray-800 p-2 text-center">{job.job_status}</td>
            <td class="border border-gray-800 p-2 text-center">{new Date(job.created_time).toLocaleString()}</td>
            <td class="border border-gray-800 p-2 text-center">
              <button class="bg-blue-500 text-white px-2 py-1 rounded" on:click={() => openJobModal(job)}>Details</button>
            </td>
          </tr>
        {/each}
      </tbody>
      {:else}
      <p class="text-gray-500">No jobs available to show</p>
      {/if}
    </table>
  </div>

  {#if selectedJob}
    <div class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
      <div class="bg-slate-800 p-4 rounded shadow-lg overflow-auto relative">
        <h2 class="text-lg font-bold">Job Details</h2>

        <button 
        class=" bg-blue-500 text-white px-4 py-2 rounded absolute top-4 right-4" 
        on:click={reRequestLLM}>
        Re-request LLM
        </button>
        
        <button 
        class=" bg-blue-800 text-white px-4 py-2 rounded absolute top-4 right-44" 
        on:click={requestC2Data}>
        CMD
        </button>

        <button 
        class=" bg-blue-800 text-white px-4 py-2 rounded absolute top-4 right-64" 
        on:click={requestMetadata}>
        Metadata
        </button>



        <div class="mt-4">
          <p><strong>Name:</strong> {selectedJob.name}</p>
          <p><strong>Run Command:</strong> {selectedJob.run_command ? 'Yes' : 'No'}</p>
          <p><strong>Run Command Args:</strong> {selectedJob.run_command_args ? selectedJob.run_command_args.join(', ') : 'None'}</p>
          <p><strong>File Args:</strong> {selectedJob.file_args ? selectedJob.file_args.join(', ') : 'None'}</p>
          <p><strong>Architecture:</strong> {selectedJob.arch}</p>
          <p><strong>Run Duration:</strong> {selectedJob.run_duration} seconds</p>
          <p><strong>LLM Response:</strong></p>
          <pre class="whitespace-pre-wrap bg-gray-100 p-2 rounded text-black overflow-auto w-[60vw] max-h-[30vw]">{selectedJob.llm_response}</pre>
        </div>
        <button class="mt-4 bg-red-500 text-white px-4 py-2 rounded" on:click={closeJobModal}>Close</button>
        <button 
          class=" bg-red-800 text-white px-4 py-2 rounded absolute bottom-4 right-4" 
          on:click={deleteJob}>
          Delete Job
        </button>
      </div>
    </div>
  {/if}

  {#if showCMDModal}
  <div class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
    <div class="bg-slate-800 p-4 rounded shadow-lg overflow-auto relative">
      <div class="mt-4">
        <pre class="whitespace-pre-wrap bg-gray-100 p-2 rounded text-black overflow-auto w-[60vw] max-h-[30vw]">{cmdData}</pre>
        <button class="mt-4 bg-red-500 text-white px-4 py-2 rounded" on:click={closeCMDModel}>Close</button>
      </div>
    </div>
  </div>
  {/if}

  {#if showMetadataModal}
  <div class="fixed inset-0 flex items-center justify-center bg-black bg-opacity-50">
    <div class="bg-slate-800 p-4 rounded shadow-lg overflow-auto relative">
      {#if !showMetadataSSLModal && !showMetadataC2Modal}
      <button class="mt-4 bg-blue-500 text-white px-4 py-2 rounded" on:click={openMetadataSSLModal}>SSL Data</button>
      {/if}
      {#if !showMetadataC2Modal && !showMetadataSSLModal}
      <button class="mt-4 bg-blue-500 text-white px-4 py-2 rounded" on:click={openMetadataC2Modal}>C2 Data</button>
      {/if}
      {#if showMetadataSSLModal}
        <div class="mt-4 h-[75vh] overflow-y-auto">
          <ul class="space-y-2">
            {#if Object.keys(metadataSSL).length ===0}
              <span class="font-semibold text-white">No SSL Data</span>
            {/if}
            {#each Object.entries(metadataSSL) as [key, value]}
              <li class="p-2 bg-white rounded border border-gray-300">
                <span class="font-semibold text-black">SSL Data:</span>
                <pre class="whitespace-pre-wrap text-black">{value}</pre>
              </li>
            {/each}
          </ul>
          <button class="mt-4 bg-red-500 text-white px-4 py-2 rounded" on:click={closeMetadataSSLModal}>Close</button>
        </div>
      {/if}
      {#if showMetadataC2Modal}
        <div class="mt-4 h-[75vh] w-[30vw] overflow-y-auto">
          {#if Object.keys(metadataC2).length ===0}
          <span class="font-semibold text-white">No C2 Data</span>
          {/if}
          <ul class="space-y-2">
            {#each Object.entries(metadataC2) as [key, value]}
              <li class="p-2 bg-white rounded border border-gray-300">
                <span class="font-semibold text-black">C2 Data:</span>
                <pre class="whitespace-pre-wrap text-black">IP/DNS: {key}  Port: {value}</pre>
              </li>
            {/each}
          </ul>
          <button class="mt-4 bg-red-500 text-white px-4 py-2 rounded" on:click={closeMetadataC2Modal}>Close</button>
        </div>
      {/if}
      {#if !showMetadataSSLModal && !showMetadataC2Modal}
      <button class="mt-4 bg-red-500 text-white px-4 py-2 rounded" on:click={closeMetadataModal}>Close</button>
      {/if}
    </div>
  </div>
  {/if}

</div>

