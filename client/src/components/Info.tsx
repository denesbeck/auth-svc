interface InfoProps {
  text: string;
}

const Info = ({ text }: InfoProps) => {
  return <p className="mb-8 text-slate-200">{text}</p>;
};

export default Info;
