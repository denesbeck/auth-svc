interface InfoProps {
  text: string;
}

const Info = ({ text }: InfoProps) => {
  return <p className="mb-8 text-dark-100">{text}</p>;
};

export default Info;
