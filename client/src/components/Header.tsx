import { SvgIconTypeMap } from "@mui/material";
import { OverridableComponent } from "@mui/material/OverridableComponent";

interface HeaderProps {
  title: string;
  icon: OverridableComponent<SvgIconTypeMap>;
  backgroundColor: string;
}
const Header = ({ title, icon, backgroundColor }: HeaderProps) => {
  const Icon = icon;
  return (
    <div className="flex items-center mb-4 space-x-3">
      <div className={`w-max p-3 ${backgroundColor} rounded-full`}>
        <Icon className="text-white min-h-8 min-w-8" />
      </div>
      <h1 className="text-2xl text-dark-200">{title}</h1>
    </div>
  );
};

export default Header;
