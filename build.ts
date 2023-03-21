import { tasks } from '@plugjs/build'
import * as dotenv from 'dotenv'

dotenv.config()
const coverageLevel = process.env.ALCATEL_HOST ? 100 : 0

export default tasks({
  minimumCoverage: coverageLevel,
  minimumFileCoverage: coverageLevel,
})
