import { useEffect, useRef } from 'react'

type ChildNodeWithId = ChildNode & { id: string }

function useClickOutside<T extends HTMLElement = HTMLElement>(
  action: (event: MouseEvent) => void,
  id?: string
) {
  const ref = useRef<T>(null)

  useEffect(() => {
    const outside = (e: MouseEvent) => {
      const el = ref?.current

      let suppressHandler = false

      // The `id` is required only for portals; otherwise, the handler will be suppressed because `lastChild` will always be `null`.
      // For portals, we need to verify whether the portal element is nested within another portal element. This ensures proper handling and prevents issues with event propagation or element hierarchy.
      if (id) {
        const portal = document.getElementById('myPortal')
        const lastChild = portal?.lastChild
        suppressHandler = (lastChild as ChildNodeWithId)?.id !== id
      }

      if (el && !suppressHandler && !el.contains(e.target as Node)) {
        action(e)
      }
    }

    document.addEventListener('mousedown', outside)

    return () => {
      document.removeEventListener('mousedown', outside)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return ref
}

export default useClickOutside
