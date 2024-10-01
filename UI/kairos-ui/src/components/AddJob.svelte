<script>
    import { env } from "$env/dynamic/public"
    export let isAddJobOpen = false;
    export let closeAddJob;
    let overrideSystemPrompt = false;
    let settings;
    let errorMessage = "";
    let isArm64 = false;

    $: arch = isArm64 ? 'arm64' : 'amd64';

    let formData = {
      keep_alive: false,
      run_duration: 5,
      run_command: false,
      run_command_args: '',
      malware_file: '',
      file_args: '',
      name: '',
      arch: '',
      save_cmd_output: false,
      bin_exclusions: '',
      system_prompt_override: "",
    }

    let fileInput;
  
    const handleSubmit = async (event) => {
      event.preventDefault();

      const file = fileInput && fileInput.files.length > 0 ? fileInput.files[0] : null;

      if(isArm64){
        formData.arch = "arm64"
      } else {
        formData.arch = "amd64"
      }

      if (file){
        const reader = new FileReader();
        reader.onloadend = async () =>{
          formData.malware_file = reader.result.split(',')[1];
          await sendPostRequest();
        };  
        reader.readAsDataURL(file);
      } else {
        await sendPostRequest();
      }
    };

    const sendPostRequest = async () => {
      const response = await fetch(env.PUBLIC_BASE_URL+'/ui/addjob',{
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(formData)
      });
      
      if (response.ok) {
        const result = await response.json();
        console.log('Success:', result);
        errorMessage = "";
        closeAddJob();
        location.reload();
      } else {
        const errorResponse = await response.json();
        console.error('Error:', errorResponse.error);
        errorMessage = "Error: " + errorResponse.error;
        setTimeout(() =>{
          errorMessage = "";
        }, 5000)
      }
    }

    async function fetchSettings(){
        const response = await fetch(env.PUBLIC_BASE_URL+'/ui/settings');
        if (response.ok){
            settings = await response.json();
            formData.system_prompt_override = settings.system_prompt || "";
        } else {
            console.error("unable to fetch settings")
        }
    }

    function handleCheckboxChange(event) {
      overrideSystemPrompt = event.target.checked;
      if (overrideSystemPrompt){
        fetchSettings()
      } else {
        formData.system_prompt_override = "";
      }
    }

    function toggleArch(){
      isArm64 = !isArm64;
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

  .toggle {
        cursor: pointer;
        padding: 10px;
        background-color: #007bff;
        color: white;
        border: none;
        border-radius: 5px;
    }
</style>

  
{#if isAddJobOpen}
  <div class="fixed inset-0 flex items-center justify-center bg-black-700 bg-opacity-80 z-20">
    <div class="bg-slate-800 rounded-lg p-6 w-96">
        <form on:submit={handleSubmit} class="space-y-4">
          <div>
            <label for="name" class="block">Name</label>
            <input type="text" bind:value={formData.name} class="form-input text-black" />
          </div>
          
          <div class="flex items-center">
            <span class="mr-2">{isArm64 ? 'arm64' : 'amd64'}</span>
            <label class="relative inline-flex items-center cursor-pointer">
                <input type="checkbox" class="sr-only" on:change={toggleArch} />
                <div class={`w-10 h-6 rounded-full shadow-inner transition-colors duration-200 ease-in-out ${isArm64 ? 'bg-green-500' : 'bg-blue-500'}`}></div>
                <div class={`absolute w-4 h-4 bg-white rounded-full shadow transition-transform duration-200 ease-in-out ${isArm64 ? 'translate-x-4' : 'translate-x-0'}`}></div>
            </label>
        </div>
          <div>
            <label for="keepAlive" class="inline-block mr-5 ">Keep Runner Alive</label>
            <input type="checkbox" bind:checked={formData.keep_alive} class="form-checkbox" />
          </div>
          <div>
            <label for="runDuration" class="inline-block mr-2">Run Duration: </label>
            <input type="number" bind:value={formData.run_duration} class="form-input w-20 text-black" />
          </div>
          <div>
            <label for="runCommand" class="inline-block mr-5">Run Command</label>
            <input type="checkbox" bind:checked={formData.run_command} class="form-checkbox" />
          </div>
          {#if formData.run_command}
          <div>
            <label for="runCommandArgs" class="block">Run Command Args</label>
            <input type="text" bind:value={formData.run_command_args} class="form-input text-black" />
          </div>
          <div>
            <label for="binExclusions" class="block">Bin Exclusions</label>
            <input type="text" bind:value={formData.bin_exclusions} class="form-input text-black" />
          </div>
          {:else}
          <div>
            <label for="malwareFile" class="block">Malware File</label>
            <input type="file" bind:this={fileInput} class="form-input" />
          </div>
          <div>
            <label for="fileArgs" class="block">File Args</label>
            <input type="text" bind:value={formData.file_args} class="form-input text-black" />
          </div>
          {/if}
          <div>
            <label for="saveCMDOutput" class="inline-block mr-5">Save CMD Output</label>
            <input type="checkbox" bind:checked={formData.save_cmd_output} class="form-checkbox" />
          </div>
          <div>
            <label for="systemPromptOverride" class="inline-block mr-5">Override System Prompt</label>
            <input type="checkbox" bind:checked={overrideSystemPrompt} class="form-checkbox" on:change={handleCheckboxChange}/>
          </div>
          {#if overrideSystemPrompt}
          <div>
            <label for="system_prompt" class="block text-sm font-medium">System Prompt:</label>
            <textarea bind:value={formData.system_prompt_override} class="mt-1 block w-full border border-gray-300 rounded-md shadow-sm focus:ring focus:ring-blue-500 focus:border-blue-500 p-2 text-black" rows="4"></textarea>
          </div>
          {/if}
      <button type="submit" class="btn  bg-blue-800 text-white font-bold py-2 px-4 rounded-full hover:bg-blue-700">Submit</button>
      <button class="mt-4 bg-red-500 text-white px-4 py-2 rounded-full hover:bg-red-600 ml-40" on:click={closeAddJob}>Close </button>
    </form>

    </div>
  </div>
{/if}

{#if errorMessage}
  <div class="error-message">
    {errorMessage}
  </div>
{/if}