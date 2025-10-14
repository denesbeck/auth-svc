/* INFO: If localId is not provided, globalId will be favored.
 * If neither localId nor globalId is provided, no event will be dispatched.
 */
const useLoading = (globalId?: string) => {
  const startLoading = (localId?: string) => {
    const id = localId || globalId
    if (!id) return
    window.dispatchEvent(new Event(`start-loading-${id}`))
  }
  const stopLoading = (localId?: string) => {
    const id = localId || globalId
    if (!id) return
    window.dispatchEvent(new Event(`stop-loading-${id}`))
  }
  return { startLoading, stopLoading }
}

export default useLoading
