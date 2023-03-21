import { tasks } from '@plugjs/build'
import * as dotenv from 'dotenv'

dotenv.config()
const enableCoverage = !! process.env.ALCATEL_HOST

export default tasks({
  coverage: enableCoverage,
  minimumCoverage: enableCoverage ? 100 : 0,
  minimumFileCoverage: enableCoverage ? 100 : 0,
})
