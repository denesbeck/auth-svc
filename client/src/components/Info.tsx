interface InfoProps {
  text: string
}

const Info = ({ text }: InfoProps) => {
  return <p className="mt-2 mb-6 text-slate-400">{text}</p>
}

export default Info
