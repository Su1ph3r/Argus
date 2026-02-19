import { createApp } from 'vue'
import { createPinia } from 'pinia'
import PrimeVue from 'primevue/config'
import App from './App.vue'
import router from './router'

// PrimeVue components
import DataTable from 'primevue/datatable'
import Column from 'primevue/column'
import Button from 'primevue/button'
import InputText from 'primevue/inputtext'
import Dropdown from 'primevue/dropdown'
import MultiSelect from 'primevue/multiselect'
import Card from 'primevue/card'
import Panel from 'primevue/panel'
import TabView from 'primevue/tabview'
import TabPanel from 'primevue/tabpanel'
import Tag from 'primevue/tag'
import ProgressSpinner from 'primevue/progressspinner'
import Toast from 'primevue/toast'
import ToastService from 'primevue/toastservice'
import Paginator from 'primevue/paginator'
import Accordion from 'primevue/accordion'
import AccordionTab from 'primevue/accordiontab'
import Dialog from 'primevue/dialog'

// Styles - Use dark theme as base since our CSS variables handle theming
import 'primevue/resources/themes/lara-dark-blue/theme.css'
import 'primevue/resources/primevue.min.css'
import 'primeicons/primeicons.css'
import './assets/styles/main.css'

const app = createApp(App)

// Plugins
app.use(createPinia())
app.use(router)
app.use(PrimeVue)
app.use(ToastService)

// Register PrimeVue components globally
app.component('DataTable', DataTable)
app.component('Column', Column)
app.component('Button', Button)
app.component('InputText', InputText)
app.component('Dropdown', Dropdown)
app.component('MultiSelect', MultiSelect)
app.component('Card', Card)
app.component('Panel', Panel)
app.component('TabView', TabView)
app.component('TabPanel', TabPanel)
app.component('Tag', Tag)
app.component('ProgressSpinner', ProgressSpinner)
app.component('Toast', Toast)
app.component('Paginator', Paginator)
app.component('Accordion', Accordion)
app.component('AccordionTab', AccordionTab)
app.component('Dialog', Dialog)

app.mount('#app')
