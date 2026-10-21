import { Link } from "react-router-dom";
import { PageHeader } from "../components/ui";

export function NotFoundPage() {
  return (
    <>
      <PageHeader
        eyebrow="404"
        title="Page not found"
        description="The route does not exist in this local workbench. No data was changed."
      />
      <p>
        <Link className="text-link" to="/">
          Return to overview
        </Link>
      </p>
    </>
  );
}
